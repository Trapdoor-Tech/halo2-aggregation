use crate::transcript::ChallengeScalarVar;

mod lookup;
mod multiopen;
mod permutation;
mod transcript;
mod vanishing;
mod verifier;

pub use verifier::VerifierChip;

#[derive(Clone, Copy, Debug)]
pub struct Theta;
type ChallengeTheta<F> = ChallengeScalarVar<F, Theta>;

#[derive(Clone, Copy, Debug)]
pub struct Beta;
type ChallengeBeta<F> = ChallengeScalarVar<F, Beta>;

#[derive(Clone, Copy, Debug)]
pub struct Gamma;
type ChallengeGamma<F> = ChallengeScalarVar<F, Gamma>;

#[derive(Clone, Copy, Debug)]
pub struct Y;
type ChallengeY<F> = ChallengeScalarVar<F, Y>;

#[derive(Clone, Copy, Debug)]
pub struct X;
type ChallengeX<F> = ChallengeScalarVar<F, X>;

#[cfg(test)]
mod tests {}
