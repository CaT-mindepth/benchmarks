//
// robust RED: https://en.wikipedia.org/wiki/Robust_random_early_detection
// diagram from the paper:
//                     +--------------+ <- drop packet feedback
//                     |              |       
//             +-------+-----+    +---+---+   
//   packet -->| RRED filter |----|  RED  |------>
//             +-------+-----+    +-------+
//                     |
//                     * drop
//
struct Packet {
  int q_inst;
  int mark; 
  int prob;
  int gain;
  int last_arrival;
};

int q_avg = 0;

int t1;
int t2;
int t_star = 10; // 10 ms
int indicator = 0; // RRED paper uses bloom filter with N bins with flows from different sources, we just use one.
                   // Hence, it is naturally the max of all N bins.
#define MAX(a, b) ((a)<(b))?(b):(a)
#define INRANGE(a,low,hi) (((a)>=(low))&&((a)<=(hi)))
void func(struct Packet p) {
  int t_max = MAX(t1,t2);
  if (INRANGE(p.arrival_time, t_max, t_max + t_star)) {
    // reduce local indicator by 1 for each bin corresponding to f
    indicator = indicator - 1;
  } else {
    // increase local indicator by 1 for each bin of f
    indicator = indicator + 1;
  }

  if (indicator >= 0) {
    // perform RED
    q_avg = (p.gain * q_avg) + (1 - p.gain) * p.q_inst;
    if (q_avg < 50) {
      p.mark = 0; // RED ok
    } else if (q_avg > 100) {
      p.mark = 1;
      // RED drops, update T2 variable in RRED
      t2 = p.arrival_time;
    } else {
      p.prob = (q_avg - 50) * 100000 / (100 - 50);
      p.mark = p.prob;
    }
  } else { // drop and update
    t1 = p.arrival_time;
    p.mark = 1; 
  }
}
