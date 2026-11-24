"""Write a compact result index from the current, measured protocol revision."""
from pathlib import Path
import argparse
import json
import os
from result_io import load_csv

ROOT=Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--directory',type=Path,default=ROOT/'results/current')
    ap.add_argument('--figures-dir',type=Path,default=ROOT/'figures/current')
    args=ap.parse_args();data=args.directory
    figure_link=Path(os.path.relpath(args.figures_dir.resolve(),data.resolve())).as_posix()
    qa=json.loads((data/'qa.json').read_text(encoding='utf-8'))
    meta=json.loads((data/'environment.json').read_text(encoding='utf-8'))
    assert qa['passed'] and meta['complete']
    ell,n,d=(meta[key] for key in ('default_ell','default_n','default_d'))
    rows=load_csv(data/'summary.csv')
    def get(s,op):
        matches=[r for r in rows if r['scheme']==s and r['operation']==op and r['experiment']=='algorithms'
                 and tuple(int(r[key]) for key in ('ell','n','d'))==(ell,n,d)]
        if len(matches)!=1:
            raise ValueError((s,op,'missing or duplicate measured operation'))
        r=matches[0]
        return f"{float(r['median_ms']):.2f} [{float(r['ci95_low_ms']):.2f}, {float(r['ci95_high_ms']):.2f}]"
    text=['# 实验结果','',
          f'四个方案采用相同 PBC 参数与编译设置。默认配置为 $n={n},d={d}$，本文使用 $\\ell={ell}$。',
          f"每组预热 {meta['warmups']} 次、测量 {qa['repetitions']} 次，保留全部记录。"
          "下表为中位数及 95% 自助置信区间，单位为 ms。",'',
          '| 方案 | 用户签发 | 签发者计算 | 呈示生成 | 呈示验证 |','| --- | ---: | ---: | ---: | ---: |']
    for s,label in [('OTAC','本文'),('ACL','ACL'),('UPROVE','U-Prove'),('CY22','Chan–Yuen（签发仅核心）')]:
        text.append('| '+label+' | '+' | '.join(get(s,op) for op in ('holder_issue','issuer_issue','show','verify'))+' |')
    text+=['',f"本文转让生成耗时 {get('OTAC','transfer')} ms，验证耗时 {get('OTAC','verify_transfer')} ms。",'',
           '本文签发需要一次用户与签发者之间的往返，链上登记及确认另计。本文呈示包含候选承诺的匿名成员证明。',
           '图 1 按凭证属性总数比较四项签发与呈示开销，图 2 按同一属性规模展示本文转让开销。'
           '图 3 固定属性总数，按匹配属性数比较呈示开销。本文在各测点使用相同候选集大小。','',
           f"逐次耗时 {qa['rows']:,} 条，独立配置/操作系列 {qa['series']} 组。通信长度由实际编码核对。",'',
           '- [通信表](communication_tables.md)', '- [原始数据](raw_timings.csv)', '- [统计汇总](summary.csv)',
           '- [环境与源码散列](environment.json)', '- [数据核验](qa.json)',
           f'- [图与 LaTeX 源文件]({figure_link}/)', '',
           '状态维护为本地原子账本接口，不包含网络和共识延迟。Chan–Yuen 未实例化的签发证明不计为零成本，完整签发结果不可用。',
           '当前服务请求未绑定验证者身份与会话随机数；实验不宣称验证了跨会话授权保护。功能检查和耗时测量不代替安全证明。','']
    path=data/'report.md';path.write_text('\n'.join(text),encoding='utf-8');print(path)


if __name__=='__main__':main()
