import os

for k in [0, 1, 2]:
    for kl in [0, 1, 2, 4, 10]:
        if kl >= k:
            os.system('python3 ground_truth_generator.py -k {k} --kl {kl} --skip-pintool -o {o}'.format(
                k=k, kl=kl,
                o='batch/gt_{}_{}'.format(k, kl)
            ))
