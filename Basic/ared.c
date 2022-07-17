//
// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.78.7450&rep=rep1&type=pdf
// Adaptive RED: An Algorithm for Increasing the Robustness of RED’s Active Queue Management
// Sally Floyd, Ramakrishna Gummadi, and Scott Shenker
// Berkeley ICSI, 2001
//
struct Packet {
  int q_inst;
  int mark; 
  int prob;
  int gain;
};

int q_avg = 0;
int alpha = 1;
// 1/0.9 = 1.11, but round up to 2.
#define BETA 2
int max_p = 0;


void func(struct Packet p) {
  q_avg = (p.gain * q_avg) + (1 - p.gain) * p.q_inst;

  // update alpha
  if (max_p / 4 <= 1) {
    alpha = max_p / 4;
  } else {
    alpha = 1;
  }

  if (q_avg < 50 && max_p >= 1) {
    p.mark = 0;
    max_p = max_p / BETA; // equivalent to max_p * 0.5
  } else if (q_avg > 100 && max_p <= 5) {
    p.mark = 1;
    max_p = max_p + alpha;
  } else {
    p.prob = (q_avg - 50) * 10 * 100 * 100 / (100 - 50);
    p.mark = p.prob;
  }
}
