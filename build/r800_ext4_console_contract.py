"""Exact inherited stdout identity observations, not SELinux opener SID."""
import re

PREFIX = b"r800-console: "
LINE = re.compile(rb"r800-console: stage=(kernel|init|client) device=(\d+):(\d+) inode=(\d+) filesystem=(\d+):(\d+)")


def inspect(log, stages, after, before):
    lines=log.replace(b"\r\n",b"\n").splitlines()
    rows=[(i,LINE.fullmatch(x)) for i,x in enumerate(lines) if x.startswith(PREFIX)]
    if len(rows)!=len(stages) or any(m is None for _,m in rows):
        raise ValueError("Missing or unavailable inherited stdout descriptor")
    if [m[1].decode("ascii") for _,m in rows]!=list(stages):
        raise ValueError("Unexpected stdout observation stages")
    identities=[tuple(int(v) for v in m.groups()[1:]) for _,m in rows]
    if identities[0][:2]!=(5,1) or not identities[0][2] or any(x!=identities[0] for x in identities):
        raise ValueError("Inherited stdout identity changed or not /dev/console")
    for (index,_),lower,upper in zip(rows,after,before):
        if not lines.index(lower)<index<lines.index(upper):
            raise ValueError("Stdout observation outside stage window")
    return {"inherited_stdout_identity_reported":True,
            "stdout_device":"5:1","stdout_inode":identities[0][2],
            "stdout_filesystem_device":f"{identities[0][3]}:{identities[0][4]}",
            "stdout_observed_stages":list(stages),
            "actual_fd_opener_sid_verified":False}
