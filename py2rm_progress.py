#!/usr/bin/python3

import rdeps
import debianbts
import argparse
import os.path
import yattag
import datetime
import popcon
import regex
from matplotlib import pyplot as plt
from collections import defaultdict
import multiprocessing as mp

# support both "TAG: pkg -- description" and "TAG: pkg"
WNPPRE = regex.compile(r'(?P<tag>[^:]+): (?P<src>[+-\.a-z0-9]*)(?:$| -- .*)')
# generate an additional level of graphs
EXTRALEVEL = 2

def log(msg):
    print(f"{datetime.datetime.now()}    {msg}")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--destdir', default=None, help='directory where to store the images')
    parser.add_argument('-l', '--limit', default=None, type=int, help='limit the lists of bugs (py2removal and WNPP) retrieved (for DEBUG)')
    parser.add_argument('-b', '--bugs', default=None, nargs='+', type=int, help='only work on the specified bugs, useful for debug')
    args = parser.parse_args()

    log('Retrieving WNPP bugs information...')
    if args.bugs:
        wnpp_bugs_ids = args.bugs
    else:
        wnpp_bugs_ids = debianbts.get_bugs('package', 'wnpp')
    if args.limit:
        wnpp_bugs_ids = wnpp_bugs_ids[:args.limit]
    log(f"Found {len(wnpp_bugs_ids)} WNPP bugs, getting status...")
    wnpp_bugs = debianbts.get_status(wnpp_bugs_ids)
    wnpp = {}
    for wnpp_bug in wnpp_bugs:
        if wnpp_bug.done:
            continue
        m = WNPPRE.match(wnpp_bug.subject)
        if m:
            tag, src = m.groups()
            wnpp[src] = (tag, wnpp_bug.bug_num)
        else:
            log(f"Badly formatted WNPP bug: retitle {wnpp_bug.bug_num} \"{wnpp_bug.subject}\"")

    log('Getting bugs tagged `py2removal`...')
    if args.bugs:
        bugs_by_tag = args.bugs
    else:
        bugs_by_tag = debianbts.get_usertag('debian-python@lists.debian.org', 'py2removal')['py2removal']
    if args.limit:
        bugs_by_tag = bugs_by_tag[:args.limit]

    log(f"Found {len(bugs_by_tag)} bugs, getting status...")
    bugs = debianbts.get_status(bugs_by_tag)

    # generate a progress graph
    d = defaultdict(int)
    for bug in bugs:
        # there are very old bugs (Jan 2018) tagged `py2removal`; they are just a handful, so let's ignore them
        if bug.done and bug.log_modified.date() >= datetime.date(2019, 7, 1):
            d[bug.log_modified.date()] += 1
    kdates, vbugs = [], []
    total = len(bugs)
    for kdate in sorted(d):
        kdates.append(kdate)
        total = total - d[kdate]  # we remove the amount of bugs closed that day from the total (whole bugs)
        vbugs.append(total)
    plt.plot(kdates, vbugs)
    plt.xticks(rotation=18, ha='right')
    plt.grid()
    plt.savefig(os.path.join(args.destdir, 'py2removal_progress.png'))

    log('Processing source packages data...')
    latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, sources = rdeps.parse_source_pkgs()

    log('Parsing bugs...')

    data = []
    for bug in bugs:
        if bug.done or bug.package == 'ftp.debian.org':
            continue
        if bug.source not in sources:
            continue
        active = False  # is this bug still active, ie a src pkg with still bin pkgs depending on py2?
        # first check the source pkg
        bdeps = []
        brdeps = 0
        for d in [2, 3, 4, 5]:
            bdeps.extend(sources[bug.source][d].replace('\n', '').split(', '))
        for bdep in bdeps:
            bdep = bdep.split(' ')[0]
            if (bdep == 'python' or bdep.startswith(('python2', 'python-', 'libpython2', 'libpython-'))) and not (bdep.endswith('-doc') or bdep.startswith('libboost-python')):
                brdeps += 1
        if brdeps > 0:
            data.append((bug.bug_num, 'src:'+bug.source, brdeps, None, sources[bug.source][6], 0, None, wnpp.get(bug.source, None), None, None))
            active = True
        for bin in sources[bug.source][1].replace('\n', '').split(', '):
            try:
                if bin not in rdeps.cache:
                    continue
                pkg = rdeps.cache[bin]
                deps = []
                for d in ['Depends', 'Recommends', 'Suggests']:
                    deps.extend(pkg.version_list[0].depends_list.get(d, []))

                # does the package depends on python2 packages?
                if any([(x[0].target_pkg.name == 'python' or
                            (x[0].target_pkg.name.startswith(('python2', 'python-', 'libpython2', 'libpython'))
                                and not (x[0].target_pkg.name.endswith('-doc')
                                         or x[0].target_pkg.name.startswith(('libboost-python', 'libpython3'))
                                        )
                            )
                        ) for x in deps]):
                    active = True
                    graph_1 = rdeps.generate_rdeps_graph(bin, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, 1)
                    graph_N = rdeps.generate_rdeps_graph(bin, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, EXTRALEVEL)
                    data.append((bug.bug_num, bin, len(set(graph_1.get_edges())), graph_1, sources[bug.source][6], len(deps), popcon.package(bin).get(bin, None), wnpp.get(bug.source, None), len(set(graph_N.get_edges())), graph_N))
            except Exception as e:
                log(f"error processing {bin}, {e}")
                import traceback; log(traceback.print_exc())
                log(f"{bug.bug_num}\t{bin}")
        if not active:
            log(f"{bug.bug_num} has no py2 dependencies?")

    log('Pre-processing graph for image generation...')

    # get a list of packages for which we have a graph, so we dont generated 404 URLs
    packages = list()
    for bugno, pkg, edges_1, graph_1, maint, fdeps, popconn, wnppp, edges_N, graph_N in data:
        if graph_1 and len(graph_1.get_edges()):
            packages.append(pkg)

    work = []
    # produce text xdot for the graphs, easier to pass to mp (Dot objs are note pickleble)
    for bugno, pkg, edges_1, graph_1, maint, fdeps, popconn, wnppp, edges_N, graph_N in data:
        if not graph_1 or pkg == 'python':
            continue
        edges_1 = graph_1.get_edges()
        if len(edges_1) > 0 and args.destdir:
            # level 1 image
            for node_1 in graph_1.get_nodes():
                node_name = node_1.get_name().replace('"', '')
                # create a link only if linking to a package part of the resultset
                if node_name in packages:
                    node_1.set_URL(node_name+'_1.svg')
            work.append((graph_1.create_xdot().decode(), os.path.join(args.destdir, f"{pkg}_1.svg")))
            # level EXTRA image
            for node_N in graph_N.get_nodes():
                node_name = node_N.get_name().replace('"', '')
                # create a link only if linking to a package part of the resultset
                if node_name in packages:
                    node_N.set_URL(node_name+f'_{EXTRALEVEL}.svg')
            work.append((graph_N.create_xdot().decode(), os.path.join(args.destdir, f"{pkg}_{EXTRALEVEL}.svg")))

    def write_svg_graph(xdot, outfile):
        import pydot
        if __name__ == '__main__':
            graph = pydot.graph_from_dot_data(xdot)[0]
        with open(outfile, 'wb') as f:
            f.write(graph.create(format='svg'))

    log('Generating images...')
    with mp.Pool(mp.cpu_count()-2) as p:
        p.starmap(write_svg_graph, work)

    log('Generating HTML page...')
    doc, tag, text = yattag.Doc().tagtext()
    with tag('html'):
        with tag('head'):
            with tag('script'):
                doc.attr(('type', 'text/javascript'))
                doc.attr(src='sorttable.js')
        with tag('body'):
            with tag('p'):
                text(f"document generated on {datetime.datetime.now(tz=datetime.timezone.utc)} .  (")
                with tag('a', target='_blank', href='https://github.com/sandrotosi/debian-tools'):
                    text('source code')
                text(")")
            with tag('p'):
                text(f"Total bugs found: {len(bugs)} (open: {len([x for x in bugs if not x.done])}, closed: {len([x for x in bugs if x.done])}).  ")
                text("See a graphical representation of the progress ")
                with tag('a', target='_blank', href='py2removal_progress.png'):
                    text('here')
                text(' (only bugs closed after 2019-07-01).')
            with tag('p'):
                text(f"Total entries below: {len(data)}")
            with tag('table', border='1', klass="sortable"):
                with tag('tr'):
                    with tag('th'):
                        with tag('b'): text('Bug No.')
                    with tag('th'):
                        with tag('b'): text('Binary pkg')
                    with tag('th'):
                        with tag('b'): text('Popcon')
                    with tag('th'):
                        with tag('b'): text('WNPP')
                    with tag('th'):
                        with tag('b'): text('Maintainer')
                    with tag('th'):
                        with tag('b'): text('# deps')
                    with tag('th'):
                        with tag('b'): text('# rdeps')
                    with tag('th'):
                        with tag('b'): text('Rdeps graph (level 1)')
                    with tag('th'):
                        with tag('b'): text(f"Rdeps graph (level {EXTRALEVEL})")
                for bugno, pkg, edges_1, graph_1, maint, fdeps, popconn, wnppp, edges_N, graph_N in sorted(data, key=lambda x: (x[2], x[5])):
                    with tag('tr'):
                        with tag('td'):
                            with tag('a', target='_blank', href=f"https://bugs.debian.org/{bugno}"):
                                text(bugno)
                        with tag('td'):
                            if pkg.startswith('src:'):
                                with tag('a', target='_blank', href=f"https://packages.debian.org/source/sid/{pkg.split(':')[1]}"):
                                    text(pkg)
                            else:
                                with tag('a', target='_blank', href=f"https://packages.debian.org/unstable/{pkg}"):
                                    text(pkg)
                        with tag('td'):
                            if popconn:
                                text(popconn)
                            else:
                                text('')
                        with tag('td'):
                            if wnppp:
                                wnpptag, wnppbug = wnppp
                                with tag('a', target='_blank', href=f"https://bugs.debian.org/{wnppbug}"):
                                    text(wnpptag)
                            else:
                                text('')
                        with tag('td'):
                            text(maint)
                        with tag('td'): text(fdeps)
                        with tag('td'): text(edges_1)
                        with tag('td'):
                            if pkg.startswith('src:'):
                                text('no graph for src pkgs (yet)')
                            else:
                                if edges_1 > 0:
                                    with tag('a', target='_blank', href=f"{pkg}_1.svg"):
                                        text('graph')
                                else:
                                    text('no rdeps')
                        with tag('td'):
                            if pkg.startswith('src:'):
                                text('no graph for src pkgs (yet)')
                            else:
                                if edges_N > 0:
                                    with tag('a', target='_blank', href=f"{pkg}_{EXTRALEVEL}.svg"):
                                        text('graph')
                                else:
                                    text('no rdeps')

    with open('%s/index.html' % args.destdir, 'w') as f:
        f.write(doc.getvalue())
