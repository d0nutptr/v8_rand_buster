from xs128p import get_args,

def main():
    """
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------
    # Relevant v8 Code to understand this solver:
    # Math.Random Implementation (https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/builtins/builtins-math-gen.cc#L402)
    #   Uses a precomputed cache of values to make subsequent calls to Math.random quick
    #   This source will refer to this as "bucketing" as it puts the random values in "buckets" that we use until they are empty.
    #   After the bucket is empty, we make a call to RefillCache (https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/math-random.cc#L36)
    #   which populates the cache (bucket) with 64 () new random values. If the cache is not empty when Math.random is called,
    #   we pop the next value off the rear of the array until we're at `MATH_RANDOM_INDEX_INDEX` == 0 again for a refill.
    #   Notable hurdles in implementation:
    #       Unlike previous and similar implementations of xs128p, Chrome only uses `state_0` for converting and storing cached randoms
    #           > (https://github.com/v8/v8/blob/4b9b23521e6fd42373ebbcb20ebe03bf445494f9/src/math-random.cc#L64)
    #           > vs (https://github.com/v8/v8/commit/ac66c97cfddc1e9fd89b494950ecf8a1a260bc80#diff-202872834c682708e9294600f73e4d15L115) (PRE SEPT 2018)
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------
    """

    multiple, gen, points = get_args()

    if gen is not None:
        state0, state1, count = gen



        for i in range(count):
            state0, state1, output = xs128p(state0, state1)
            print(math.floor(multiple * to_double(output)))
    else:
        state0, state1 = solve(points, multiple)

        if state0 is not None and state1 is not None:
            print("{},{}".format(state0, state1))


main()
