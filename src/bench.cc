#include <array>
#include <stdint.h>
#include <utility>
#include <sstream>

#include <benchmark/../../src/statistics.h>
#include <benchmark/../../src/cycleclock.h>
#include <benchmark/benchmark.h>

#include "pqscake.h"
#include "utils.h"

extern const size_t alg_num;

void BenchScheme(benchmark::State &st) {
    size_t total=0, t;
    part_t parts[2];
    bool label_st=false;
    std::ostringstream ost;

    uint8_t alg_id = st.range(0);
    uint8_t session_key_resp[MAX_SEC_BYTE_LEN] = {0},
            session_key_init[MAX_SEC_BYTE_LEN] = {0};
    for (auto _ : st) {
        comm_ctx_t session = {0};
        init_party(&parts[0], kInit, alg_id);
        init_party(&parts[1], kResp, alg_id);
        init_session(&session, parts);

        if(!label_st) {
            ost << "\tData transer: ["
                << "lpk: " << get_received_init_data_len(&session)
                << "\tek_t,sign_A: " << get_session_sent_data_len(&session)
                << "\tC,C_T,c: " << get_session_received_data_len(&session)
                << "\ttotal: " << get_session_sent_data_len(&session) +
                get_session_received_data_len(&session) +
                (2*get_received_init_data_len(&session)) << "],"
                << "\tNIST-LVL: " << get_scheme_sec(&session);
            st.SetLabel(ost.str());
            label_st = true;
        }

        t = benchmark::cycleclock::Now();
        offer(&session, &parts[0]);
        accept(session_key_resp, &session, &parts[1]);
        finalize(session_key_init, &session, &parts[0]);
        total += benchmark::cycleclock::Now() - t;

        clean_session(&session);
        clean_party(&parts[0]);
        clean_party(&parts[1]);
    }
    // CPU cycles are not affected by memory allocations, but timing is
    st.counters["CPU cycles: mean"] = benchmark::Counter(
        total, benchmark::Counter::kAvgIterations | benchmark::Counter::kResultNoFormat);
}

int main(int argc, char** argv) {
    for (size_t i=0; i<alg_num; i++) {
        RegisterBenchmark(get_alg_params(i)->alg_name, BenchScheme)
            ->Unit(benchmark::kMicrosecond)
            ->Arg(i);
    }

    init_lib();
    ::benchmark::Initialize(&argc, argv);
    ::benchmark::RunSpecifiedBenchmarks();
}
