#!/usr/bin/python3

import apt_pkg
import sys
import pydot
import debian.deb822 as d822
from collections import defaultdict
import argparse
# for visualization, check https://github.com/jrfonseca/xdot.py/blob/master/sample.py
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import xdot


# binary packages relationships we're interested in, so ignore Conflicts/Breaks/etc
RELS = ['Depends', 'Recommends', 'Suggests', ]

apt_pkg.init_config()
apt_pkg.init_system()
cache = apt_pkg.Cache(None)


def parse_source_pkgs():
    # HACK! get the latest binary packags for every source pkg
    # if there are cruft binary packgaes they dont get removed automatically
    # so parse the source entries, and just keep the ones with the highest version
    # (ie the latest uploaded); dont care much about proper version comparison
    sources = dict()
    for suite in ['main', 'contrib', 'non-free', ]:
        for x in d822.Sources.iter_paragraphs(open(f"/var/lib/apt/lists/ftp.debian.org_debian_dists_unstable_{suite}_source_Sources")):
            if x['Package'] not in sources:
                sources[x['Package']] = (x['Version'], x['Binary'], x.get('Build-Depends', ''), x.get('Build-Depends-Indep', ''), x.get('Build-Depends-Arch', ''), x.get('Testsuite-Triggers', ''), x['Maintainer'], x.get('Uploaders', ''))
            else:
                v = sources[x['Package']][0]
                if x['Version'] > v:
                    sources[x['Package']] = (x['Version'], x['Binary'], x.get('Build-Depends', ''), x.get('Build-Depends-Indep', ''), x.get('Build-Depends-Arch', ''), x.get('Testsuite-Triggers', ''), x['Maintainer'], x.get('Uploaders', ''))

    latestbinpkgs = set()
    for k in sources.keys():
        latestbinpkgs.update(set(sources[k][1].split(', ')))

    rbdeps = defaultdict(list)
    rbdepsi = defaultdict(list)
    rbdepsa = defaultdict(list)
    rtstrig = defaultdict(list)
    for src in sources.keys():
        for bd in sources[src][2].split(', '):
            if bd:
                rbdeps[bd.split()[0]].append(src)
        for bdi in sources[src][3].split(', '):
            if bdi:
                rbdepsi[bdi.split()[0]].append(src)
        for bda in sources[src][4].split(', '):
            if bda:
                rbdepsa[bda.split()[0]].append(src)
        for tstrig in sources[src][5].split(', '):
            if tstrig:
                rtstrig[tstrig.split()[0]].append(src)

    return latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, sources


def generate_rdeps_graph(pkg_name, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, maxlevel):
    visited = set()
    graph = pydot.Dot(graph_type='digraph', simplify=False)
    todo = list()
    # list, "heap", of (package-name, level) so we can skip the highest levels down the recursion
    todo.append((pkg_name, 1))

    while len(todo):
        name, level = todo.pop()
        graph.add_node(pydot.Node(name))
        if name not in latestbinpkgs:
            continue
        if name in visited:
            continue
        if level > maxlevel:
            continue
        visited.add(name)
        if name not in cache:
            continue
        pkg = cache[name]
        rdeps = pkg.rev_depends_list
        for rdep in rdeps:
            if rdep.parent_pkg.name not in latestbinpkgs:
                continue
            if rdep.dep_type in RELS:
                graph.add_node(pydot.Node(rdep.parent_pkg.name))
                graph.add_edge(pydot.Edge(rdep.parent_pkg.name, name, label=rdep.dep_type+f" (lvl={level})"))
                todo.append((rdep.parent_pkg.name, level+1))
        for rbdep in rbdeps[name]:
            graph.add_node(pydot.Node(rbdep))
            graph.add_edge(pydot.Edge(rbdep, name, label=f"Build-Depends (lvl={level})"))
        for rbdepi in rbdepsi[name]:
            graph.add_node(pydot.Node(rbdepi))
            graph.add_edge(pydot.Edge(rbdepi, name, label=f"Build-Depends-Indep (lvl={level})"))
        for rbdepa in rbdepsa[name]:
            graph.add_node(pydot.Node(rbdepa))
            graph.add_edge(pydot.Edge(rbdepa, name, label=f"Build-Depends-Arch (lvl={level})"))
        for rtstrigg in rtstrig[name]:
            graph.add_node(pydot.Node(rtstrigg))
            graph.add_edge(pydot.Edge(rtstrigg, name, label=f"Testsuite-Triggers (lvl={level})"))

    return graph


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--level', '-l', dest='level', default=2, type=int,
                        help='maximum level of recursion, default 2')
    parser.add_argument('--text', '-t', dest='text', default=False, action="store_true",
                        help='print a text representation, instead of a graph')
    parser.add_argument('pkgs', nargs='+', help='list of packages to analize, currently only the first is accepted')
    args = parser.parse_args()

    if not args.text:
        print('Parsing Sources Index...')

    latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, sources = parse_source_pkgs()

    if not args.text:
        print(f"Processing reverse dependencies (with max {args.level} depth level)...")


    graph = generate_rdeps_graph(args.pkgs[0], latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, args.level)

    #with open('image.png', 'wb') as f:
    #    f.write(graph.create(format='png'))

    if args.text:
        edges = graph.get_edges()
        print(f"Total remaining reverse dependencies: {len(edges)}")
        for edge in edges:
            print(f"{edge.get_destination()} <- {edge.get_source()}  ({edge.get_label()})")
    else:
        # show the graph in a separate window
        window = xdot.DotWindow()
        window.set_dotcode(str(graph).encode())
        window.connect('delete-event', Gtk.main_quit)
        Gtk.main()

