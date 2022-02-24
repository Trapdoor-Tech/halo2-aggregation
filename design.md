# Aggregation Design

## Outer circuit that aggregates 1 inner circuit

To verify a single inner circuit, we need to 

1. assign proof from instance, i.e. there must be copy constraints between proof and public inputs;
  
   a proof consists of 
   - several polynomial commitments `C_i`
   - the evaluation of polynomials at challenge points `eval_i`
   
2. assign instance_commitments from instance, i.e. the instance commitments of inner circuit appears in the outer circuit's instance column.

    Note that the instance commitment is calculated from inner circuit's public inputs.

3. assign transcript from instance, i.e. the challenges that are computed by transcript must be provided by contract as instance.
    
    - `theta`
    - `beta`
    - `gamma`
    - `y`
    - `x`

4. assign 4 polynomial commitments `(e_input, f_input, w_input, zw_input)` from instance.
   
   We will compare these four commitments with that we calculated from inner circuit's proof `(e, f, w, zw)`. That is, we assert the following conditions hold:
   - `e_input = e`
   - `f_input = f`
   - `w_input = w`
   - `zw_input = zw`
   
5. pairing check of `(e_input, f_input, w_input, zw_input)` is performed in contract, instead of inside the outer circuit.

## Outer circuit that aggregates `n` inner circuits
For each inner circuit, use the above steps to prepare public inputs for outer circuit.

Note that each inner circuit will produce `(e_i, f_i, w_i, zw_i)`, we will use these data to compute a random challenge `t` using some cheap(cost very less gas) hash function `H`, i.e. `t = H(e_0, f_0, w_0, zw_0, e_1, f_1, w_1, zw_1, ...)`.

`t` is passed to outer circuit as public instance. `t` is computed by contract. 

Then we invoke four MSM to compute four points `(E, F, W, ZW)` using the following equations:
> `E = \sum_i t^i e_i`

> `F = \sum_i t^i f_i`

> `W = \sum_i t^i w_i`

> `ZW = \sum_i t^i zw_i`

These four points are made public in outer circuit's instance column. And we use pairing check on them inside the contract.