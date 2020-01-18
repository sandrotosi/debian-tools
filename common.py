import debian.deb822 as d822
from collections import defaultdict
import apt_pkg


def parse_source_pkgs(distro='unstable'):
    # HACK! get the latest binary packags for every source pkg
    # if there are cruft binary packgaes they dont get removed automatically
    # so parse the source entries, and just keep the ones with the highest version
    # (ie the latest uploaded); dont care much about proper version comparison
    sources = dict()
    for suite in ['main', 'contrib', 'non-free', ]:
        for x in d822.Sources.iter_paragraphs(open(f"/var/lib/apt/lists/ftp.debian.org_debian_dists_{distro}_{suite}_source_Sources")):
            if x['Package'] not in sources:
                sources[x['Package']] = (x['Version'], x['Binary'], x.get('Build-Depends', ''), x.get('Build-Depends-Indep', ''), x.get('Build-Depends-Arch', ''), x.get('Testsuite-Triggers', ''), x['Maintainer'], x.get('Uploaders', ''))
            else:
                v = sources[x['Package']][0]
                if apt_pkg.version_compare(x['Version'], v) > 0:
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


def is_python2_dep(dep):
    if dep.startswith(('python', 'libpython', 'cython'))\
            and not (dep.endswith(('-doc', '-docs', '-common', '-examples', '-data', '-test', '-tpl'))
                     or dep.startswith(('python3', 'libboost-python', 'libpython3', 'python-gi-dev', 'cython3', 'python-pip-whl', 'python-odf-tools', 'pythonpy'))):
        return dep
    return False
