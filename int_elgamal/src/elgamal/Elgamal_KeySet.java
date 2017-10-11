package elgamal;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.security.SecureRandom;
import java.math.BigInteger;
/**
 *
 * @author oorestisime
 */
public class Elgamal_KeySet {
    private Elgamal_PublicKey pk;
    private Elgamal_SecretKey sk;
    private Elgamal_Parameters params;
    private int nb_bits;
    int g;
    
    public Elgamal_KeySet(Elgamal_PublicKey _pk,Elgamal_SecretKey _sk,int nbb){
        this.pk=_pk;
        this.sk=_sk;
       this.nb_bits=nbb; 
    }
    public Elgamal_KeySet(int nbb){
        //System.out.print(nbb);
        Elgamal_KeySet(new Elgamal_Parameters(nbb,new SecureRandom())); 
    }
    public void Elgamal_KeySet(Elgamal_Parameters par){
        this.params=par;
        this.nb_bits=par.getNb_bits();
        int p = Elgamal.getPrime_cert(nb_bits, this.params.getPrg(), 100);
        int p_prime=(p-1)/2;
        //System.out.println("p---->"+p+"  et  p prime   "+p_prime);

        boolean found=false;
        do{
        	   SecureRandom gs = new SecureRandom();
               int g = gs.nextInt(p);
                if(p > g && ((g^p_prime)% p)== 1 && (g^2 % p) != 1){
                    found=true;
                }
            } while(!found);
  
        //System.out.println("g  -> "+g);
        found=false;
        int x;
        do{
        	SecureRandom gs = new SecureRandom();
        	x = gs.nextInt(p);
        	if(p > g && p_prime < x){
            found=true;
        	}
        }while(p_prime < x);
        //System.out.println("x  -> "+x);
        int h=g ^x%p;
        //System.out.println("h  -> "+h);
        Elgamal_PublicKey pk=new Elgamal_PublicKey(p,h,g);
        Elgamal_SecretKey sk=new Elgamal_SecretKey(p,x);
        this.pk=pk;
        this.sk=sk;
    }

    /**
     * @return the pk
     */
    public Elgamal_PublicKey getPk() {
        return pk;
    }

    /**
     * @return the sk
     */
    public Elgamal_SecretKey getSk() {
        return sk;
    }

    /**
     * @return the params
     */
    public Elgamal_Parameters getParams() {
        return params;
    }

    /**
     * @return the nb_bits
     */
    public int getNb_bits() {
        return nb_bits;
    }
    
}