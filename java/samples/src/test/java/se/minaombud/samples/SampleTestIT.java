package se.minaombud.samples;

import org.junit.jupiter.api.Test;

public class SampleTestIT {

    @Test
    void arkiveringSample() throws Exception {
        ArkiveringSample.main(new String[0]);
    }

    @Test
    void endUserSample() throws Exception {
        EndUserSample.main(new String[0]);
    }

    @Test
    void systemServiceSample() throws Exception {
        SystemServiceSample.main(new String[0]);
    }

}
