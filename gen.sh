rm -f ~/.viminfo

python3 syscall_tracer.py -c "vim" -a action.act --wd ./vimworkspace
python3 ground_truth_generator.py -k 2 --kl 4 -o output/test/ground_truth
