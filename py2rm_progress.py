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
import matplotlib.dates as mdates
from collections import defaultdict, Counter, namedtuple
import multiprocess as mp
import subprocess
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import lxml.html
import requests

# support both "TAG: pkg -- description" and "TAG: pkg"
WNPPRE = regex.compile(r'(?P<tag>[^:]+): (?P<src>[^ ]+)(?:$| -- .*)')
# RM: pkg -- reasons"
FTPDORE = regex.compile(r'RM: (?P<src>[^ ]+)(?:$| -- .*)')
# generate an additional level of graphs
EXTRALEVEL = 2

# namedtuple to hold the data we care for py2removal
dataitem = namedtuple('dataitem', ['bugno', 'pkg', 'edges_1', 'graph_1', 'maint', 'uplds', 'fdeps', 'popcon', 'wnppp', 'edges_N', 'graph_N', 'py3k_pkgs_avail', 'real_rdeps'])


def log(msg):
    print(f"{datetime.datetime.now()}    {msg}")


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--destdir', default=None, help='directory where to store the images')
    parser.add_argument('-l', '--limit', default=None, type=int, help='limit the lists of bugs (py2removal and WNPP) retrieved (for DEBUG)')
    parser.add_argument('-b', '--bugs', default=None, nargs='+', type=int, help='only work on the specified bugs, useful for debug')
    parser.add_argument('--no-blocks', default=False, action="store_true", help='dont sent blocks updates to control@ (for DEBUG)')
    parser.add_argument('--no-images', default=False, action="store_true", help='dont generate images (for DEBUG)')
    parser.add_argument('--no-pypi', default=False, action="store_true", help='dont look for modules on PyPI (for DEBUG)')
    args = parser.parse_args()

    if not os.path.isdir(args.destdir):
        os.makedirs(args.destdir)

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

    log('Retrieving ftp.debian.org bugs information...')
    if args.bugs:
        ftpdo_bugs_ids = args.bugs
    else:
        ftpdo_bugs_ids = debianbts.get_bugs('package', 'ftp.debian.org')
    if args.limit:
        ftpdo_bugs_ids = ftpdo_bugs_ids[:args.limit]
    log(f"Found {len(ftpdo_bugs_ids)} ftp.debian.org bugs, getting status...")
    ftpdo_bugs = debianbts.get_status(ftpdo_bugs_ids)
    ftpdo = {}
    for ftpdo_bug in ftpdo_bugs:
        if ftpdo_bug.done:
            continue
        if ftpdo_bug.subject.startswith('RM'):
            m = FTPDORE.match(ftpdo_bug.subject)
            if m:
                src = m.group(1)
                ftpdo[src] = ftpdo_bug.bug_num
            else:
                log(f"Badly formatted ftp.debian.org bug: retitle {ftpdo_bug.bug_num} \"{ftpdo_bug.subject}\"")

    log('Getting bugs tagged `py2removal`/`py2keep`...')
    if args.bugs:
        bugs_by_tag = args.bugs
        py2keep_bugs_by_tag = []
    else:
        bugs_by_tag = debianbts.get_usertag('debian-python@lists.debian.org', 'py2removal')['py2removal']
        py2keep_bugs_by_tag = debianbts.get_usertag('debian-python@lists.debian.org', 'py2keep')['py2keep']
    if args.limit:
        bugs_by_tag = bugs_by_tag[:args.limit]
        py2keep_bugs_by_tag = py2keep_bugs_by_tag[:args.limit]

    log(f"Found {len(bugs_by_tag)} `py2removal` bugs, getting status...")
    bugs = debianbts.get_status(bugs_by_tag)
    log(f"Found {len(py2keep_bugs_by_tag)} `py2keep` bugs, getting status...")
    py2keep_bugs = debianbts.get_status(py2keep_bugs_by_tag)

    # get the tags, so we can show them on the table
    bugs_tags = {}
    bugs_blockedby = {}
    bugs_by_source = {}
    sources_by_bug = {}
    bugs_by_bugno = {}
    bugs_done = set()
    for bug in bugs:
        bugs_tags[bug.bug_num] = bug.tags
        bugs_blockedby[bug.bug_num] = bug.blockedby
        bugs_by_source[bug.source] = bug.bug_num
        bugs_by_bugno[bug.bug_num] = bug
        sources_by_bug[bug.bug_num] = bug.source
        if bug.done:
            bugs_done.add(bug.bug_num)

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
    # how many bugs are tagged 'pending'?
    pendings = len([bug.bug_num for bug in bugs if 'pending' in bug.tags and not bug.done])
    plt_locator = mdates.DayLocator(interval=7)
    plt_formatter = mdates.AutoDateFormatter(plt_locator)
    fig, ax = plt.subplots()
    ax.xaxis.set_major_locator(plt_locator)
    ax.xaxis.set_major_formatter(plt_formatter)
    if len(vbugs) > 1:
        ax.plot(kdates, vbugs, label=f"open bugs ({vbugs[-1]})")
        # show a vertical line from the last date for the bugs tagged pending
        ax.plot([kdates[-1], kdates[-1]], [vbugs[-1], vbugs[-1]-pendings], label=f"bugs tagged 'pending' ({pendings})")
    plt.xticks(rotation=18, ha='right')
    plt.grid()
    fig.tight_layout()
    ax.legend(loc='lower left')
    plt.savefig(os.path.join(args.destdir, 'py2removal_progress.png'))

    # generate an unofficial leaderboard
    topN = 20
    doers = Counter([bug.done_by for bug in bugs if bug.done])
    top_doers = doers.most_common(topN)
    other_doers = doers.most_common()[topN:]
    fig, ax = plt.subplots()
    fig.set_size_inches(9.6, 7.2)
    plt.title(f"Unofficial top {topN} py2removal leaderboard (as of {datetime.datetime.now(tz=datetime.timezone.utc)})")
    for name, v in top_doers:
        plt.bar(regex.sub(' <.*>', '', name), v)
    # group up the remaining uploaders in a single bar
    plt.bar(f"Others ({len(other_doers)})", sum(x[1] for x in other_doers))
    plt.xticks(rotation=25, ha='right')
    fig.tight_layout()
    ax.yaxis.grid()
    plt.savefig(os.path.join(args.destdir, 'leaderboard.png'), )

    log('Processing source packages data...')
    latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, sources = rdeps.parse_source_pkgs()

    # what source produces a binary
    bin_to_src = {}
    for source in sources:
        for bin in sources[source][1].replace('\n', '').split(', '):
            bin_to_src[bin] = source

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
        # these are not really reverse build depends, these are the packages the src pkg b-deps on
        brdeps = 0
        for d in [2, 3, 4, 5]:
            bdeps.extend(sources[bug.source][d].replace('\n', '').split(', '))
        for bdep in bdeps:
            bdep = bdep.split(' ')[0]
            if (bdep.startswith(('python', 'libpython'))) and not (bdep.endswith(('-doc', '-examples')) or bdep.startswith(('python3', 'libboost-python', 'libpython3'))):
                brdeps += 1
        if brdeps > 0:
            data.append(dataitem(bug.bug_num, 'src:'+bug.source, 0, None, regex.sub(' \<[^<>]+\>', '', sources[bug.source][6]), regex.sub(' \<[^<>]+\>', '', sources[bug.source][7]), brdeps, None, wnpp.get(bug.source, None), None, None, None, real_rdeps=0))
            active = True
        bins = sources[bug.source][1].replace('\n', '').split(', ')
        for bin in bins:
            try:
                if bin not in rdeps.cache:
                    continue
                pkg = rdeps.cache[bin]
                deps = []
                # some packages are purely virtual, ie not available on my arch (amd64); skip them
                if not pkg.version_list:
                    continue
                for d in ['Depends', 'Recommends']:#, 'Suggests']:
                    deps.extend(pkg.version_list[0].depends_list.get(d, []))
                # does the package depends on python2 packages?
                if any([(y.target_pkg.name.startswith(('python', 'libpython'))
                            and not (y.target_pkg.name.endswith(('-doc', '-examples'))
                                     or y.target_pkg.name.startswith(('libboost-python', 'libpython3', 'python3'))
                                    )
                        ) for x in deps for y in x]):
                    active = True
                    graph_1 = rdeps.generate_rdeps_graph(bin, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, 1)
                    graph_N = rdeps.generate_rdeps_graph(bin, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, EXTRALEVEL)

                    # very brutal heuristic to know if debian has a py3k package already
                    py3k_pkgs_avail = None
                    if bin.startswith('python-') and not bin.endswith(('-doc', 'dbg')):
                        if bin.replace('python-', 'python3-') in latestbinpkgs:
                            py3k_pkgs_avail = True
                        else:
                            py3k_pkgs_avail = False
                    # deps from packages outside of the same source
                    real_rdeps = len(set(edge.get_source().replace('"', '') for edge in graph_1.get_edges()) - set(bins))
                    data.append(dataitem(bug.bug_num, bin, len(set(graph_1.get_edges())), graph_1, regex.sub(' \<[^<>]+\>', '', sources[bug.source][6]), regex.sub(' \<[^<>]+\>', '', sources[bug.source][7]), len(deps), popcon.package(bin).get(bin, None), wnpp.get(bug.source, None), len(set(graph_N.get_edges())), graph_N, py3k_pkgs_avail, real_rdeps=real_rdeps))
            except Exception as e:
                log(f"error processing {bin}, {e}")
                import traceback; log(traceback.print_exc())
                log(f"{bug.bug_num}\t{bin}")
        if not active:
            log(f"{bug.bug_num} has no py2 dependencies?")

    if not args.no_images:
        log('Pre-processing graph for image generation...')

        # get a list of packages for which we have a graph, so we dont generated 404 URLs
        packages = list()
        for dta in data:
            if dta.graph_1 and len(dta.graph_1.get_edges()):
                packages.append(dta.pkg)

        work = []
        # produce text xdot for the graphs, easier to pass to mp (Dot objs are note pickleble)
        for dta in data:
            if not dta.graph_1 or dta.pkg == 'python':
                continue
            edges_1 = dta.graph_1.get_edges()
            if len(edges_1) > 0 and args.destdir:
                # level 1 image
                for node_1 in dta.graph_1.get_nodes():
                    node_name = node_1.get_name().replace('"', '')
                    # create a link only if linking to a package part of the resultset
                    if node_name in packages:
                        node_1.set_URL(node_name+'_1.svg')
                work.append((dta.graph_1, os.path.join(args.destdir, f"{dta.pkg}_1.svg")))
                # level EXTRA image
                for node_N in dta.graph_N.get_nodes():
                    node_name = node_N.get_name().replace('"', '')
                    # create a link only if linking to a package part of the resultset
                    if node_name in packages:
                        node_N.set_URL(node_name+f'_{EXTRALEVEL}.svg')
                work.append((dta.graph_N, os.path.join(args.destdir, f"{dta.pkg}_{EXTRALEVEL}.svg")))

        def write_svg_graph(graph, outfile):
            graph.set_rankdir('RL')
            with open(outfile, 'wb') as f:
                f.write(graph.create(format='svg'))

        log('Generating images...')
        with mp.Pool(mp.cpu_count()-2) as p:
            p.starmap(write_svg_graph, work)

    pypi = {}
    if not args.no_pypi:
        log('Gathering PyPI data...')
        # list of modules on PyPI
        pypi_pkgs_page = requests.get("https://pypi.org/simple/")
        tree = lxml.html.fromstring(pypi_pkgs_page.content)
        pypi_pkgs = set([package.lower() for package in tree.xpath('//a/text()')])
        log(f'Found {len(pypi_pkgs)} PyPI packages, checking...')
        for dta in data:
            # trying to figure out a matching name debian <-> PyPI...
            pkg2find = None
            if dta.pkg in pypi_pkgs:
                pkg2find = dta.pkg
            elif dta.pkg.startswith('python-') and dta.pkg.replace('python-', '') in pypi_pkgs:
                pkg2find = dta.pkg.replace('python-', '')
            elif dta.pkg.startswith('src:') and dta.pkg.replace('src:', '') in pypi_pkgs:
                pkg2find = dta.pkg.replace('src:', '')
            elif 'py' + dta.pkg in pypi_pkgs:
                pkg2find = 'py' + dta.pkg
            if pkg2find:
                try:
                    pkginfo = requests.get(f'https://pypi.org/pypi/{pkg2find}/json').json()['info']
                    available_versions = [classif.split(" :: ")[-1] for classif in pkginfo['classifiers'] if classif.startswith('Programming Language :: Python')]
                    if available_versions:
                        pypi[dta.pkg] = {'version': pkginfo['version'], 'available_versions': available_versions}
                except:
                    pass  # ignore errors here


    log('Generating HTML page...')

    # make sure we have a copy of tablefilter, https://www.tablefilter.com; it's not pretty, but it works
    tablefilter_dir = os.path.join(args.destdir, 'TableFilter')
    if not os.path.isdir(tablefilter_dir):
        subprocess.call('git clone --quiet --depth 1 https://github.com/koalyptus/TableFilter %s' % tablefilter_dir, shell=True)
    else:
        subprocess.call('git -C %s pull --quiet' % tablefilter_dir, shell=True)

    tablefilter_config = '''
var tfConfig = {
    base_path: '%s',
    state: {
          types: ['local_storage'],
          filters: true,
          sort: true,
    },
    alternate_rows: true,
    rows_counter: {
        text: 'Total entries: '
    },
    btn_reset: {
        text: 'Clear'
    },
    col_types: [
        'number',
        'string',
        'string',
        'string',
        'number',
        'string',
        'string',
        'number',
        'number',
        'number',
        'string',
        'string'
    ],
    loader: true,
    no_results_message: true,
    sticky_headers: true,

    extensions: [{ name: 'sort' }]
};
var tf = new TableFilter('py2rm-table', tfConfig);
tf.init();
    ''' % 'TableFilter/dist/tablefilter/'

    doc, tag, text = yattag.Doc().tagtext()
    with tag('html'):
        with tag('head'):
            with tag('script'):
                doc.attr(('type', 'text/javascript'))
                doc.attr(src='TableFilter/dist/tablefilter/tablefilter.js')
        with tag('body'):
            with tag('p'):
                text(f"document generated on {datetime.datetime.now(tz=datetime.timezone.utc)} .  (")
                with tag('a', target='_blank', href='https://github.com/sandrotosi/debian-tools'):
                    text('source code')
                text(")")
            with tag('p'):
                text(f"Total bugs found: {len(bugs)} (open: {len([x for x in bugs if not x.done])}, closed: {len([x for x in bugs if x.done])}).  ")
                text("Progress ")
                with tag('a', target='_blank', href='py2removal_progress.png'):
                    text('chart')
                text(' (only bugs closed after 2019-07-01).  Unofficial ')
                with tag('a', target='_blank', href='leaderboard.png'):
                    text('leaderboard')
                text('.')
            with tag('table', id="py2rm-table", klass="TF"):
                with tag('thead'):
                    with tag('tr'):
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('Bug No.')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('Binary pkg')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('py3k?')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('span', title='Latest version and PyPI classifiers Python versions'):
                                with tag('b'): text('PyPI Data')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('Popcon')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('WNPP/ftp.d.o')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('Maintainer/Uploaders')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('# deps')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('# rdeps')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('span', title='Reverse dependencies from packages not in the same source pkgs'):
                                with tag('b'): text('# real rdeps')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text('Rdeps graph (level 1)')
                        with tag('th', _sorttype="string", style="cursor: pointer;"):
                            with tag('b'): text(f"Rdeps graph (level {EXTRALEVEL})")
                for dta in sorted(data, key=lambda x: (x.real_rdeps, x.fdeps)):
                    with tag('tr'):
                        with tag('td'):
                            with tag('a', target='_blank', href=f"https://bugs.debian.org/{dta.bugno}"):
                                text(dta.bugno)
                            btags = ''
                            if 'pending' in bugs_tags[dta.bugno]:
                                btags += 'P'
                            if 'patch' in bugs_tags[dta.bugno]:
                                btags += '+'
                            if btags:
                                text(' ' + btags)
                        with tag('td'):
                            if dta.pkg.startswith('src:'):
                                with tag('a', target='_blank', href=f"https://packages.debian.org/source/sid/{dta.pkg.split(':')[1]}"):
                                    text(dta.pkg)
                            else:
                                with tag('a', target='_blank', href=f"https://packages.debian.org/unstable/{dta.pkg}"):
                                    text(dta.pkg)
                        with tag('td'):
                            if dta.py3k_pkgs_avail is None:
                                text('')
                            elif dta.py3k_pkgs_avail:
                                text('yes')
                            else:
                                text('no')
                        with tag('td'):
                            if dta.pkg in pypi:
                                text(f'{pypi[dta.pkg]["version"]}: {", ".join(pypi[dta.pkg]["available_versions"])}')
                            else:
                                text('')
                        with tag('td'):
                            if dta.popcon:
                                text(dta.popcon)
                            else:
                                text('')
                        with tag('td'):
                            if dta.wnppp:
                                wnpptag, wnppbug = dta.wnppp
                                with tag('a', target='_blank', href=f"https://bugs.debian.org/{wnppbug}"):
                                    text(wnpptag)
                            elif dta.pkg.replace('src:', '') in ftpdo:
                                with tag('a', target='_blank', href=f"https://bugs.debian.org/{ftpdo[dta.pkg.replace('src:', '')]}"):
                                    text('RM')
                            else:
                                text('')
                        with tag('td'):
                            with tag('b'):
                                text('M: ' + dta.maint)
                            if dta.uplds:
                                with tag('i'):
                                    text(' - U: ' + dta.uplds)
                        with tag('td'): text(dta.fdeps)
                        with tag('td'): text(dta.edges_1)
                        with tag('td'): text(dta.real_rdeps)
                        with tag('td'):
                            if dta.pkg.startswith('src:'):
                                text('no graph for src pkgs (yet)')
                            else:
                                if dta.edges_1 > 0:
                                    with tag('a', target='_blank', href=f"{dta.pkg}_1.svg"):
                                        text('graph')
                                else:
                                    text('no rdeps')
                        with tag('td'):
                            if dta.pkg.startswith('src:'):
                                text('no graph for src pkgs (yet)')
                            else:
                                if dta.edges_N > 0:
                                    with tag('a', target='_blank', href=f"{dta.pkg}_{EXTRALEVEL}.svg"):
                                        text('graph')
                                else:
                                    text('no rdeps')
            with tag('script'):
                text(tablefilter_config)

    with open('%s/index.html' % args.destdir, 'w') as f:
        f.write(doc.getvalue())

    # we can opt-out from sending mails to control@, useful for debug
    if not args.no_blocks:
        log('Generating control@ email to update block information...')
        all_bugs_blocks = defaultdict(set)
        for dta in data:
            current_blocks = set()
            if dta.bugno in all_bugs_blocks:
                current_blocks = all_bugs_blocks[dta.bugno]
            current_blocks = current_blocks.union(set(bugs_blockedby.get(dta.bugno, [])))
            all_blocks = set()
            if dta.edges_1 > 0:
                for edge in dta.graph_1.get_edges():
                    edgesrc = edge.get_source().replace('"', '')
                    if edge.get_label().lower().startswith(('build', 'testsuite')):
                        src = edgesrc
                    else:
                        src = bin_to_src[edgesrc]
                    if src not in bugs_by_source.keys():
                        log(f"ERROR: {src} found but no bug is open for that source")
                    else:
                        current_bug = bugs_by_source[src]
                        if current_bug not in bugs_done:
                            all_blocks.add(current_bug)
            new_blocks = all_blocks - current_blocks - set([dta.bugno,])
            all_bugs_blocks[dta.bugno] = all_bugs_blocks[dta.bugno].union(new_blocks)

        blocks_mail_body = []
        for bug, blocks in all_bugs_blocks.items():
            if not blocks:
                continue
            blocks_mail_body.append(f"# {sources_by_bug[bug]}")
            # there is a limit of 998 chars for a mail line, so let's split in chunks of N bugs and produce multiple commands
            N = 20
            lblocks = list(blocks)
            for chunk in  [lblocks[i * N:(i + 1) * N] for i in range((len(lblocks) + N - 1) // N )]:
                blocks_mail_body.append(f'block {bug} by {" ".join(map(str, chunk))}')

        # send the mail to control@, only if we have something to send
        if blocks_mail_body:
            mail_preamble = ['# Part of the effort for the removal of python from bullseye', '#  * https://wiki.debian.org/Python/2Removal', '#  * http://sandrotosi.me/debian/py2removal/index.html', '']
            s = smtplib.SMTP(host='localhost', port=25)
            msg = MIMEMultipart()
            msg['From'] = 'Sandro Tosi <morph@debian.org>'
            msg['To'] = 'control@bugs.debian.org'
            msg['Cc'] = 'Sandro Tosi <morph@debian.org>'
            msg['Subject'] = f"py2removal blocks updates - {datetime.datetime.now(tz=datetime.timezone.utc)}"
            msg.attach(MIMEText('\n'.join(mail_preamble + blocks_mail_body), 'plain'))
            log(msg)
            s.send_message(msg)

    log('Generating control@ email to raise severity to RC...')
    rc_severity_body = []
    for dta in data:
        try:
            if bugs_by_bugno[dta.bugno].blockedby:
                continue
            # skip this part if the bug is marked as `py2keep` or the severity is already `serious`
            if dta.bugno not in py2keep_bugs_by_tag and bugs_by_bugno[dta.bugno].severity != 'serious' and not dta.pkg.endswith('-doc') :
                if dta.pkg.startswith('python-') and dta.real_rdeps == 0:
                    rc_severity_body.append(f'# {dta.pkg} is a module and has 0 external rdeps')
                    rc_severity_body.append(f'severity {dta.bugno} serious')
                elif not dta.pkg.startswith(('python-', 'src:')) and dta.popcon and dta.popcon < 300:
                    rc_severity_body.append(f'# {dta.pkg} is an application and has low popcon ({dta.popcon} < 300)')
                    rc_severity_body.append(f'severity {dta.bugno} serious')
        except:
            print(dta)
    with open('%s/would_raise_to_rc.txt' % args.destdir, 'w') as f:
        f.write('\n'.join(rc_severity_body))

    log('Script completed')
