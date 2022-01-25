use crate::transcript::ChallengeScalarVar;

mod lookup;
mod multiopen;
mod permutation;
mod transcript;
mod vanishing;
mod verifier;
pub mod aggregation;

pub use verifier::VerifierChip;
pub use verifier::VerifierConfig;

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

// U is used in constructing lc between point sets
#[derive(Clone, Copy, Debug)]
pub struct U;
type ChallengeU<F> = ChallengeScalarVar<F, U>;

// V is used in constructing lc within a point set
#[derive(Clone, Copy, Debug)]
pub struct V;
type ChallengeV<F> = ChallengeScalarVar<F, V>;

#[cfg(test)]
mod tests {}
