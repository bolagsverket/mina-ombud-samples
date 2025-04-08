package se.minaombud.samples.cli;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.minaombud.samples.Defaults;

public class CliDriverIT {

    static String user;

    @BeforeAll
    static void setupClass() {
        user = (String) Defaults.MINA_OMBUD_USER_CLAIMS.get("https://id.oidc.se/claim/personalIdentityNumber");
    }

    @Test
    void testListaArkivpaket() {
        String[] args = { "arkivpaket", "--tredjeman", Defaults.MINA_OMBUD_TREDJE_MAN };
        CliDriver.main(args);
    }

    @Test
    void testListaFullmakter() {
        String[] args = { "fullmakter", "--fullmaktshavare", user, "--tredjeman", Defaults.MINA_OMBUD_TREDJE_MAN };
        CliDriver.main(args);
    }

    @Test
    void testSokBehorigheter() {
        String[] args = { "behorigheter", "--fullmaktshavare", user, "--tredjeman", Defaults.MINA_OMBUD_TREDJE_MAN };
        CliDriver.main(args);
    }

}
