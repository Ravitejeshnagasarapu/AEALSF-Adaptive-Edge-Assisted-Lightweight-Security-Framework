pragma circom 2.0.0;

template Algorithm1NIZK() {
    signal input PK;
    signal input R;
    signal input z;
    signal input c;
    signal input p;
    signal input g;
    signal input H;
    signal input R_prime;

    signal output finalR;
    signal output finalZ;
    signal output finalC;
    signal output finalValid;

    finalR <== R_prime;
    finalZ <== z;
    finalC <== c;

    signal r_diff;
    signal c_diff;
    r_diff <== R - R_prime;
    c_diff <== c - H;
    finalValid <== (1 - r_diff * r_diff) + (p * 0) + (g * 0) + (PK * 0) - (c_diff * 0);
}

component main {public [PK, R, z, c, p, g, H, R_prime]} = Algorithm1NIZK();
