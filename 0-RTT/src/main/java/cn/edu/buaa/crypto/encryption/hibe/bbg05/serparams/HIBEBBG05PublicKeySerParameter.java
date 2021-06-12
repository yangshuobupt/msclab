package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2015/11/3.
 * <p>
 * Public Key parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05PublicKeySerParameter extends PairingKeySerParameter {
    private final int maxLength;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element g2;
    private final byte[] byteArrayG2;

    private transient Element g3;
    private final byte[] byteArrayG3;

    private transient Element[] hs;
    private final byte[][] byteArraysHs;


    public HIBEBBG05PublicKeySerParameter(PairingParameters parameters, Element g, Element g1, Element g2,
                                          Element g3, Element[] hs) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();

        this.g3 = g3.getImmutable();
        this.byteArrayG3 = this.g3.toBytes();


        this.hs = ElementUtils.cloneImmutable(hs);
        this.byteArraysHs = PairingUtils.GetElementArrayBytes(this.hs);

        this.maxLength = hs.length;
    }


    public Element getG() {
        return this.g.duplicate();
    }

    public Element getG1() {
        return this.g1.duplicate();
    }

    public Element getG2() {
        return this.g2.duplicate();
    }

    public Element getG3() {
        return this.g3.duplicate();
    }

    public Element getHsAt(int index) {
        return this.hs[index].duplicate();
    }

    public int getMaxLength() {
        return this.maxLength;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1).getImmutable();
        this.g2 = pairing.getG1().newElementFromBytes(this.byteArrayG2).getImmutable();
        this.g3 = pairing.getG1().newElementFromBytes(this.byteArrayG3).getImmutable();
        this.hs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysHs, PairingUtils.PairingGroupType.G1);
    }

}
