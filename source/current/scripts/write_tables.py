"""Export communication comparisons from actual measured payload lengths."""
from pathlib import Path
import argparse
import json
from result_io import load_csv

ROOT=Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory',type=Path,default=ROOT/'results/current')
    args=ap.parse_args()
    data=args.directory
    meta=json.loads((data/'environment.json').read_text(encoding='utf-8'))
    qa=json.loads((data/'qa.json').read_text(encoding='utf-8'))
    assert meta['complete'] and qa['passed']
    ell,n,d=(meta[key] for key in ('default_ell','default_n','default_d'))
    rows=[r for r in load_csv(data/'communication.csv') if r['experiment']=='algorithms'
          and tuple(int(r[key]) for key in ('ell','n','d'))==(ell,n,d)]
    def value(s,q):
        selected=[r for r in rows if r['scheme']==s and r['quantity']==q]
        if len(selected)!=1:raise ValueError((s,q,'missing or duplicate quantity'))
        return int(selected[0]['bytes'])
    text=['# 最新构造的通信开销', '',
          f'默认配置为 $\\ell={ell},n={n},d={d}$，单位为 B。密码学负载与实际封装分列。', '',
          '| 本文输出 | 密码学负载 | 规范封装后 |','| --- | ---: | ---: |',
          f"| 签发申请 | {value('OTAC','issuance_request'):,} | {value('OTAC','request_wire'):,} |",
          f"| 凭证 | {value('OTAC','credential'):,} | {value('OTAC','credential'):,} |",
          f"| 完整消费输出 | {value('OTAC','presentation'):,} | {value('OTAC','show_wire'):,} |",
          f"| 完整转让公开输出 | {value('OTAC','transfer'):,} | {value('OTAC','transfer_wire'):,} |",'',
          '| 方案 | 首次签发总通信 | 凭证 | 完整属性呈示 |',
          '| --- | ---: | ---: | ---: |']
    for s,label in [('OTAC','本文'),('ACL','ACL'),('UPROVE','U-Prove'),('CY22','Chan–Yuen')]:
        q='issuance_core_lower_bound' if s=='CY22' else 'issuance_total'
        caveat='（核心下界）' if s=='CY22' else ''
        text.append(f"| {label} | {value(s,q):,}{caveat} | {value(s,'credential'):,} | {value(s,'presentation'):,} |")
    native=meta['native_parameters']
    private_handoff=native['group_bytes']+(n+1)*native['scalar_bytes']
    transfer_total=private_handoff+value('OTAC','transfer')
    text+=['',
           f"用户与签发者之间的签发负载为 {value('OTAC','issuance_bilateral'):,} B。",
           '',
           f'转让时，原持有者先私下交付旧承诺和开口，密码字段共 {private_handoff:,} B。'
           f'连同公开提交共 {transfer_total:,} B，另计保密信道封装和确认回执。',
           '', '本文总签发负载含一次链上登记。U-Prove/ACL 为本仓库的 PBC 协议复现；Chan–Yuen 未包含未实例化的加密相关证明，不能与完整签发量等同。',
           '', '转让功能只对本文测量；不把其它方案未实现的转让标成零成本。', '']
    path=data/'communication_tables.md';path.write_text('\n'.join(text),encoding='utf-8');print(path)


if __name__=='__main__':main()
