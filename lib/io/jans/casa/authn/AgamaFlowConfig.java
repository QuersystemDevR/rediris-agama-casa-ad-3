package io.jans.casa.authn;

import io.jans.orm.annotation.AttributeName;
import io.jans.orm.annotation.DataEntry;
import io.jans.orm.annotation.ObjectClass;

@DataEntry
@ObjectClass("agmFlow")
public class AgamaFlowConfig {

    @AttributeName(name = "agFlowMeta")
    private String meta;

    public String getDn()            { return dn; }
    public void   setDn(String dn)   { this.dn = dn; }
    public String getMeta()          { return meta; }
    public void   setMeta(String m)  { this.meta = m; }

}
