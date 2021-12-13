use crate::transcript::ChallengeScalarVar;

mod lookup;
mod permutation;
mod transcript;
mod vanishing;

#[derive(Clone, Copy, Debug)]
struct Theta;
type ChallengeTheta<F> = ChallengeScalarVar<F, Theta>;

#[derive(Clone, Copy, Debug)]
struct Beta;
type ChallengeBeta<F> = ChallengeScalarVar<F, Beta>;

#[derive(Clone, Copy, Debug)]
struct Gamma;
type ChallengeGamma<F> = ChallengeScalarVar<F, Gamma>;

#[derive(Clone, Copy, Debug)]
struct Y;
type ChallengeY<F> = ChallengeScalarVar<F, Y>;

#[derive(Clone, Copy, Debug)]
struct X;
type ChallengeX<F> = ChallengeScalarVar<F, X>;

#[cfg(test)]
mod tests {}
