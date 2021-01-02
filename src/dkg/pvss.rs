use algebra::{
    CanonicalDeserialize, CanonicalSerialize, PairingEngine, Read, SerializationError, Write, Zero,
};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PVSSShare<E: PairingEngine> {
    pub f_i: Vec<E::G1Affine>,
    pub u_i_2: E::G2Affine,
    pub a_i: Vec<E::G1Affine>,
    pub y_i: Vec<E::G2Affine>,
}

impl<E: PairingEngine> PVSSShare<E> {
    pub fn empty(degree: usize, num_participants: usize) -> Self {
        PVSSShare {
            f_i: vec![E::G1Affine::zero(); degree + 1],
            u_i_2: E::G2Affine::zero(),
            a_i: vec![E::G1Affine::zero(); num_participants],
            y_i: vec![E::G2Affine::zero(); num_participants],
        }
    }

    pub fn aggregate(&self, other: &Self) -> Self {
        Self {
            f_i: self
                .f_i
                .iter()
                .zip(other.f_i.iter())
                .map(|(f1, f2)| *f1 + *f2)
                .collect::<Vec<_>>(),
            u_i_2: self.u_i_2 + other.u_i_2,
            a_i: self
                .a_i
                .iter()
                .zip(other.a_i.iter())
                .map(|(a1, a2)| *a1 + *a2)
                .collect::<Vec<_>>(),
            y_i: self
                .y_i
                .iter()
                .zip(other.y_i.iter())
                .map(|(y1, y2)| *y1 + *y2)
                .collect::<Vec<_>>(),
        }
    }
}

pub struct PVSSShareSecrets<E: PairingEngine> {
    pub f_0: E::Fr,
    pub my_secret: E::G2Affine,
}
