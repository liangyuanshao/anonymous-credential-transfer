"""Check measured message sizes against the manuscript equations."""
from pathlib import Path
import argparse
import json
from collections import Counter
from benchmark_config import DEFAULT_ELL
from figure_support import sha
from result_io import load_csv
from plot_results import expected_points, summarize

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory',type=Path,default=ROOT/'results/current')
    ap.add_argument('--repetitions',type=int)
    ap.add_argument('--grid',choices=('all','default','wide'))
    args=ap.parse_args()
    data=args.directory
    meta=json.loads((data/'environment.json').read_text(encoding='utf-8'))
    assert meta['complete'] and meta['source_unchanged'] and meta['binary_unchanged']
    raw_path=data/'raw_timings.csv'
    assert sha(raw_path)==meta['raw_sha256']
    repetitions=meta['repetitions']
    if args.repetitions is not None:
        assert args.repetitions==repetitions,'Repetition count differs from the measured run'
    grid=meta.get('grid') or meta['command'][5]
    if args.grid is not None:
        assert args.grid==grid,'Grid differs from the measured run'
    default=(meta['default_ell'],meta['default_n'],meta['default_d'])
    assert default[0]==DEFAULT_ELL
    expected=expected_points(grid,default[0])
    expected_configs=len({(exp,ell,n,d) for exp,scheme,op,ell,n,d in expected})
    expected_series=len(expected)
    summary,count=summarize(raw_path,repetitions,default[0],grid=grid)
    def workload(row):
        return tuple(int(row[key]) for key in ('ell','n','d'))
    assert {workload(row) for row in summary if row['experiment']=='algorithms'}=={default}
    assert all(int(row['ell'])==DEFAULT_ELL for row in summary)
    assert count==expected_series*repetitions and len(summary)==expected_series

    sizes=load_csv(data/'communication.csv')
    native=meta['native_parameters']
    bg,bq=native['group_bytes'],native['scalar_bytes']
    show_version=native.get('show_wire_version','OAS2')
    proof_overhead={'OAS2':2*bg+bq,'OAS3':0}[show_version]
    public_overhead={'OAS2':3*bg,'OAS3':bg}[show_version]
    configurations={(r['experiment'],*workload(r)) for r in summary if r['scheme']=='OTAC'}
    assert len(configurations)==expected_configs
    checked=set()
    for r in sizes:
        if r['scheme']!='OTAC':
            continue
        ell,n,d=workload(r)
        configuration=(r['experiment'],ell,n,d)
        assert configuration in configurations,configuration
        m=(ell-1).bit_length()
        u=n-d
        show_proof=8*m*bg+(3*m+u+1)*bq+proof_overhead
        presentation=ell*bg+public_overhead+show_proof
        expected={
            'issuance_request':6*bg+(n+2)*bq,
            'credential':2*bg+bq,
            'issuance_bilateral':8*bg+(n+3)*bq,
            'issuance_total':10*bg+(n+4)*bq,
            'show_proof':show_proof,
            'presentation':presentation,
            'transfer_proof':(8*m+5)*bg+(3*m+n+3)*bq,
            'transfer':(ell+8*m+7)*bg+(3*m+n+3)*bq,
            'request_wire':6*bg+(n+2)*bq+8,
            'show_wire':presentation+12,
            'transfer_wire':(ell+8*m+7)*bg+(3*m+n+3)*bq+12,
        }
        q=r['quantity']
        key=(*configuration,q)
        assert q in expected and key not in checked,key
        assert int(r['bytes'])==expected[q],(r,expected[q])
        checked.add(key)
    checks=len(checked)
    assert checks==11*len(configurations),(checks,'Missing payload or wire length')
    assert all(r['operation_complete']==0 for r in summary if r['scheme']=='CY22' and r['operation'].endswith('issue'))
    report=dict(passed=True,rows=count,series=len(summary),repetitions=repetitions,grid=grid,
        default_ell=default[0],default_n=default[1],default_d=default[2],
        communication_equation_checks=checks,all_rows_retained=True,
        counts_by_scheme=dict(Counter(r['scheme'] for r in load_csv(raw_path))),
        source_stable_during_measurement=True,
        complete_cy22_issuance_claimed=False,
        limitations=['No consensus/network timing','No nonce in manuscript service request',
                     'Tests do not replace cryptographic security proofs'])
    (data/'qa.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
