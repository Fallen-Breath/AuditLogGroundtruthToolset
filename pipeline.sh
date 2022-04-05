if [ $# != 1 ] ; then
  echo "USAGE: $0 <command>"
  echo " e.g.: $0 vim"
  exit 1;
fi

echo "Sampling syscall traces..."
python3 hotspot_finder.py -c "$1" -t pin -k 2 -o hotspots.txt

echo "Recording ground truth data..."
python3 ground_truth_generator.py -c "$1" -k 2 -i hotspots.txt
