package cn.edu.buaa.crypto.encryption.fspibme.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;


public class FSPIBMEKeySerParameter {
    private transient String[] rho;
    private transient Map<String, PairingKeySerParameter> tk;

    public FSPIBMEKeySerParameter(PairingParameters pairingParameters, String[] rho, Map<String, PairingKeySerParameter> tk) {
        this.tk = new HashMap<String, PairingKeySerParameter>();
        this.tk = tk;
        this.rho = rho;
    }

    public String[] getRho() {
        return rho;
    }

    public void setRho(String[] rho) {
        this.rho = rho;
    }

    public Map<String, PairingKeySerParameter> getTk() {
        return tk;
    }

    public void setTk(Map<String, PairingKeySerParameter> tk) {
        this.tk = tk;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream) throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        this.elementIds = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementIds, PairingUtils.PairingGroupType.Zr);
        this.a0 = pairing.getG1().newElementFromBytes(this.byteArrayA0).getImmutable();
        this.a1 = pairing.getG1().newElementFromBytes(this.byteArrayA1).getImmutable();
        this.bs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysBs, PairingUtils.PairingGroupType.G1);
    }
}
