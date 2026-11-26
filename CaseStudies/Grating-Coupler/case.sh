#!/bin/bash
# Grating coupler case study: solve one design, optimize the coupler, or draw the README figures.
# ./case.sh --help lists the commands.
set -e
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat <<'EOF'
usage: ./case.sh <command> [options]

Grating coupler case study: solve one design, optimize the coupler, or draw the README figures.

commands:
  run [-n N] [--design D] [--resolution R] [--out DIR] [--no-field-export]
            mesh one design with mesh.py and solve it with grating_coupler.py under pymufem;
            -n N: MPI ranks or OpenMP threads (pymufem); defaults: --design published,
            --resolution nominal, --out results_<design>
  optimize  the Ax optimization: python optimize.py (see python optimize.py --help)
  figures   the figures of the README: python figures.py (see python figures.py --help),
            under xvfb-run on a machine without a display

examples:
  ./case.sh run --design published
  ./case.sh run -n 8 --design optimized
  ./case.sh optimize --trials 60
  ./case.sh figures
EOF
}

run() {
    local n="" design=published resolution=nominal out="" field_export=""
    while [ $# -gt 0 ]; do
        case $1 in
            -n) n=$2; shift 2 ;;
            --design) design=$2; shift 2 ;;
            --resolution) resolution=$2; shift 2 ;;
            --out) out=$2; shift 2 ;;
            --no-field-export) field_export=--no-field-export; shift ;;
            -h|--help) usage; exit 0 ;;
            *) echo "case.sh run: unknown option '$1'" >&2; exit 1 ;;
        esac
    done
    out=${out:-$here/results_$(basename "${design%.json}")}

    # Meshing in a process of its own: gmsh in the solver's process pins its OpenMP threads to one core.
    python "$here/mesh.py" --design "$design" --resolution "$resolution" --out "$out/mesh.msh"
    pymufem $n "$here/grating_coupler.py" --design "$design" --mesh "$out/mesh.msh" --out "$out" $field_export
}

command=${1:-}
shift || true
case $command in
    run) run "$@" ;;
    optimize) exec python "$here/optimize.py" "$@" ;;
    figures)
        if [ -z "${DISPLAY:-}" ]; then
            exec xvfb-run -a python "$here/figures.py" "$@"
        fi
        exec python "$here/figures.py" "$@" ;;
    -h|--help|"") usage ;;
    *) echo "case.sh: unknown command '$command'" >&2; usage >&2; exit 1 ;;
esac
