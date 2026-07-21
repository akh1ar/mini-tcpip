set pagination off

break rtx_resend_oldest
run

echo \n=== HIT 1: first resend (conn 1, echo "Shahnawaz") — state BEFORE resend ===\n
print t->state
print/x t->rtx[0].seq
print t->rtx[0].seg_len
print/x t->rtx[0].flags
print t->rtx[0].retransmitted
x/5c t->rtx[0].data
print t->rtt_sampling
print t->rto
print g_now_ms
print t->rtx_deadline_ms

echo \n=== finish: let the resend complete, then re-inspect (Khan's mark) ===\n
finish
print tcp_conns[0].rtx[0].retransmitted
print tcp_conns[0].rtt_sampling

echo \n=== conditional break: only when the backoff ladder is 3+ deep ===\n
condition 1 t->rtx_retries >= 3
continue
print t->rtx_retries
print t->rto
x/8c t->rtx[0].data

echo \n=== watchpoint: watch conn-2's rto double on each timeout ===\n
delete 1
watch tcp_conns[1].rto
continue
continue

echo \n=== cleanup: run to completion ===\n
delete
continue
