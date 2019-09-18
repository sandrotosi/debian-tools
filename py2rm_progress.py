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

# support both "TAG: pkg -- description" and "TAG: pkg"
WNPPRE = regex.compile(r'(?P<tag>[^:]+): (?P<src>.*)(?: -- .*)?')

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--destdir', default=None, help='directory where to store the images')
    args = parser.parse_args()

    print('Retrieving WNPP bugs information...')
    wnpp_bugs = debianbts.get_status(debianbts.get_bugs('package', 'wnpp'))
    wnpp = {}
    for wnpp_bug in wnpp_bugs:
        if wnpp_bug.done:
            continue
        m = WNPPRE.match(wnpp_bug.subject)
        if m:
            tag, src = m.groups()
            wnpp[src] = (tag, wnpp_bug.bug_num)
        else:
            print(f"Badly formatted WNPP bug: retitle {wnpp_bug.bug_num} \"{wnpp_bug.subject}\"")

    print('Getting bugs tagged `py2removal`...')
    bugs_by_tag = debianbts.get_usertag('debian-python@lists.debian.org', 'py2removal')['py2removal']

    print(f"Found {len(bugs_by_tag)} bugs, getting status...")
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

    print('Processing source packages data...')
    latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, sources = rdeps.parse_source_pkgs()

    print('Parsing bugs...')

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
            data.append((bug.bug_num, 'src:'+bug.source, brdeps, "", sources[bug.source][5], 0, None, wnpp.get(bug.source, None)))
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
                if any([(x[0].target_pkg.name == 'python' or (x[0].target_pkg.name.startswith(('python2', 'python-', 'libpython2', 'libpython'))
                                                              and not (x[0].target_pkg.name.endswith('-doc') or x[0].target_pkg.name.startswith('libboost-python')))) for x in deps]):
                    active = True
                    graph = rdeps.generate_rdeps_graph(bin, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, 1)
                    edges = graph.get_edges()
                    data.append((bug.bug_num, bin, len(set(edges)), f"{bin}.png", sources[bug.source][5], len(deps), popcon.package(bin).get(bin, None), wnpp.get(bug.source, None)))
                    if len(edges) > 0 and args.destdir:
                        with open(os.path.join(args.destdir, f"{bin}.png"), 'wb') as f:
                            f.write(graph.create(format='png'))
            except Exception as e:
                print(f"error processing {bin}, {e}")
                import traceback; print(traceback.print_exc())
                print(f"{bug.bug_num}\t{bin}\t{len(set(edges))}")
        if not active:
            print(f"{bug.bug_num} has no py2 dependencies?")

    doc, tag, text = yattag.Doc().tagtext()

    with tag('html'):
        with tag('head'):
            with tag('script'):
                doc.attr(('type', 'text/javascript'))
                doc.attr(src='sorttable.js')
        with tag('body'):
            with tag('p'):
                text(f"document generated on {datetime.datetime.now(tz=datetime.timezone.utc)}")
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
                        with tag('b'): text('Rdeps graph')
                for bugno, pkg, rdeps, imagename, maint, fdeps, popconn, wnppp in sorted(data, key=lambda x: (x[2], x[5])):
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
                        with tag('td'): text(rdeps)
                        with tag('td'):
                            if pkg.startswith('src:'):
                                text('no graph for src pkgs (yet)')
                            else:
                                if rdeps > 0:
                                    with tag('a', target='_blank', href=imagename):
                                        text('graph')
                                else:
                                    text('no rdeps')

    with open('%s/index.html' % args.destdir, 'w') as f:
        f.write(doc.getvalue())
