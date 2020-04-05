#!/usr/bin/python3

import apt_pkg
import sys
import pydot
import argparse
# for visualization, check https://github.com/jrfonseca/xdot.py/blob/master/sample.py
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
import xdot
from common import parse_source_pkgs


# binary packages relationships we're interested in, so ignore Conflicts/Breaks/etc
RELS = ['Depends', 'Recommends']#, 'Suggests', ]

apt_pkg.init_config()
apt_pkg.init_system()
cache = apt_pkg.Cache(None)


def generate_rdeps_graph(pkg_name, latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, maxlevel, testing_sources=None, testing_binaries=None, unstable_sources=None):
    visited = set()
    graph = pydot.Dot(graph_type='digraph', simplify=False, rankdir='RL')
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
        same_source_bins = [v[1].split(', ') for k, v in unstable_sources.items() if name in v[1].split(', ')][0]
        for rdep in rdeps:
            if rdep.parent_pkg.name not in latestbinpkgs:
                continue
            if rdep.dep_type in RELS:
                sourcepkg = [k for k, v in unstable_sources.items() if rdep.parent_pkg.name in v[1].split(', ')][0]
                color = 'red'
                if testing_binaries and rdep.parent_pkg.name not in testing_binaries:
                    color = 'green'
                if rdep.parent_pkg.name in same_source_bins:
                    color = 'orange'
                if rdep.parent_pkg.section == 'metapackages' or unstable_sources[sourcepkg][8] == 'metapackages':
                    color = 'turquoise'
                if rdep.parent_pkg.section.startswith(('contrib/', 'non-free/')):
                    color = 'yellow4'
                graph.add_node(pydot.Node(rdep.parent_pkg.name, color=color))
                graph.add_edge(pydot.Edge(rdep.parent_pkg.name, name, label=rdep.dep_type+f" (lvl={level})"))
                todo.append((rdep.parent_pkg.name, level+1))
        for rbdep in rbdeps[name]:
            color = 'red'
            if testing_sources and rbdep not in testing_sources:
                color = 'green'
            if rbdep in same_source_bins:
                color = 'orange'
            graph.add_node(pydot.Node(rbdep, color=color))
            graph.add_edge(pydot.Edge(rbdep, name, label=f"Build-Depends (lvl={level})"))
        for rbdepi in rbdepsi[name]:
            color = 'red'
            if testing_sources and rbdepi not in testing_sources:
                color = 'green'
            if rbdepi in same_source_bins:
                color = 'orange'
            graph.add_node(pydot.Node(rbdepi, color=color))
            graph.add_edge(pydot.Edge(rbdepi, name, label=f"Build-Depends-Indep (lvl={level})"))
        for rbdepa in rbdepsa[name]:
            color = 'red'
            if testing_sources and rbdepa not in testing_sources:
                color = 'green'
            if rbdepa in same_source_bins:
                color = 'orange'
            graph.add_node(pydot.Node(rbdepa, color=color))
            graph.add_edge(pydot.Edge(rbdepa, name, label=f"Build-Depends-Arch (lvl={level})"))
        for rtstrigg in rtstrig[name]:
            color = 'red'
            if testing_sources and rtstrigg not in testing_sources:
                color = 'green'
            if rtstrigg in same_source_bins:
                color = 'orange'
            graph.add_node(pydot.Node(rtstrigg, color=color))
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
    testing_latestbinpkgs, _, _, _, _, testing_sources = parse_source_pkgs(distro='testing')

    if not args.text:
        print(f"Processing reverse dependencies (with max {args.level} depth level)...")

    graph = generate_rdeps_graph(args.pkgs[0], latestbinpkgs, rbdeps, rbdepsi, rbdepsa, rtstrig, args.level, testing_sources=testing_sources, testing_binaries=testing_latestbinpkgs, unstable_sources=sources)

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

