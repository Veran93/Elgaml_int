package elgamal;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */





/**
 *
 * @author oorestisime
 */
public class Elgamal_PublicKey {
    private int p;
    private int h;
    private int g;
    
    public Elgamal_PublicKey(int p,int h,int g){
     this.p=p;
     this.h=h;
     this.g=g;
   }

    /**
     * @return the p
     */
    public int getP() {
        return p;
    }

    /**
     * @return the h
     */
    public int getH() {
        return h;
    }

    /**
     * @return the g
     */
    public int getG() {
        return g;
    }
    
}