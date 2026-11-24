"""Render the archived computation measurements on a common attribute-count grid."""

import argparse
from pathlib import Path

from benchmark_config import WIDE_ATTRIBUTE_COUNTS
from figure_support import ROOT, render
from plot_issuance_timing import SCHEMES, draw_figure, read_wide_summary
from result_io import save_csv


FIGURES = (
    ("figure_2_issuance_costs", SCHEMES, (("holder_issue", "Holder issuance"),
                                         ("issuer_issue", "Issuer issuance"))),
    ("figure_3_transfer_costs", ("OTAC",), (("transfer", "Transfer generation"),
                                            ("verify_transfer", "Transfer verification"))),
    ("figure_4_presentation_costs", SCHEMES, (("show", "Presentation generation"),
                                              ("verify", "Presentation verification"))),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path,
                        default=ROOT / "results" / "attribute-scale-20261108" / "summary.csv")
    parser.add_argument("--figures", type=Path,
                        default=ROOT / "figures" / "computation-by-attributes")
    args = parser.parse_args()

    requested = [(scheme, operation) for _, schemes, panels in FIGURES
                 for scheme in schemes for operation, _ in panels]
    entries = read_wide_summary(args.summary, requested)
    args.figures.mkdir(parents=True, exist_ok=True)
    for stem, schemes, panels in FIGURES:
        draw_figure(
            args.figures,
            stem,
            [(operation, title,
              {scheme: [entries[n, scheme, operation] for n in WIDE_ATTRIBUTE_COUNTS]
               for scheme in schemes}) for operation, title in panels],
            shared_y=True,
        )
    save_csv(args.figures / "computation_source_data.csv",
             [entries[key] for key in sorted(entries)])
    render(args.figures, "computation")


if __name__ == "__main__":
    main()
