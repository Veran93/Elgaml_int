package elgamal;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */



import chiffrement.CipherScheme;
import java.io.UnsupportedEncodingException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author oorestisime
 */
public class Elgamal implements CipherScheme {

    private int nbits;
    private Elgamal_KeySet kset;
    
    public Elgamal(int nb_bits){
        this.nbits=nb_bits;
        Elgamal_Parameters params=new Elgamal_Parameters(this.nbits,new SecureRandom());
        this.kset=new Elgamal_KeySet(this.nbits);
    }
    
    public Elgamal(Elgamal_KeySet _keys,int nbb){
        this.kset=_keys;
        this.nbits=nbb;
    }
    public static int getPrime(int nb_bits, Random rng){
       int fois=2;
       int p_prime,p;
       do{
         p_prime=int.probablePrime(nb_bits,rng);
         p=p_prime.multiply(fois).add(int.ONE);
       }while(!p.isProbablePrime(100));
       return p;
    }
    
    public static int getPrime_cert(int nb_bits, Random rng,int cert){
       int fois=2;
       int p_prime,p;
       do{
         p_prime=int.probablePrime(nb_bits-1,rng);
         p=p_prime.multiply(fois).add(int.ONE);
       }while(!p.isProbablePrime(cert));
       
       return p;
    }
    public Elgamal_CipherText encrypt(Elgamal_PlainText pt){
        int modulo=kset.getPk().getP();
        Elgamal_CipherText ct;
        int mhr[]=new int[pt.getPt().length];
        int r;
        do{
            r = new int(modulo.bitCount()-1, new SecureRandom());
        }while(kset.getPk().getP().compareTo(r)==-1);
        
        
        
        // changed mhr[i]
        
/*
        for(int i=0;i<pt.getPt().length;i++){
           if(pt.getPt()[i].compareTo(modulo)==1){
                //System.out.println("mod "+ modulo+" bytes  "+modulo.bitCount()+" "+pt.getPt()[i]);
                System.out.println("Plain text superieure a N");
                System.exit(1);
            } 
           //System.out.println("mod "+ modulo+" bytes  "+modulo.bitCount()+" "+pt.getPt()[i]);
           mhr[i]=(pt.getPt()[i].multiply(kset.getPk().getH().modPow(r, modulo))).mod(modulo);
        }
*/
        for(int i=0;i<pt.getPt().length;i++){
           if(pt.getPt()[i].compareTo(modulo)==1){
                //System.out.println("mod "+ modulo+" bytes  "+modulo.bitCount()+" "+pt.getPt()[i]);
                System.out.println("Plain text superieure a N");
                System.exit(1);
            } 
//           System.out.println("mod "+ modulo+" bytes  "+modulo.bitCount()+" "+pt.getPt()[i]);
           //System.out.println(pt.getPt()[i]);
           mhr[i]=(kset.getPk().getG().modPow(pt.getPt()[i],modulo).multiply(kset.getPk().getH().modPow(r, modulo))).mod(modulo);
        }
        
        

        int gr=kset.getPk().getG().modPow(r,modulo);
        ct=new Elgamal_CipherText(mhr,gr);
        return ct;
    }
    
    

    //inserted getter methods ...
    public int geteg(){
	return kset.getPk().getG();
    }

    public int getepk(){
	return kset.getPk().getH();
    }
    
    public int getp(){
	return kset.getPk().getP();
    }
    
    public int gets(){
	return kset.getSk().getX();
    }    

    public Elgamal_CipherText encrypt(String s){
        Elgamal_CipherText cipherT;
        byte bytes[]=null;
        try {
            bytes = s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Elgamal.class.getName()).log(Level.SEVERE, null, ex);
        }
        //System.out.print(bytes.length+"\n");
        byte[][] chuncked =divideArray(bytes, 31);
        //System.out.println("remainder is "+ s.length()%127);
        //last byte[]. we have to delete zeros in the end!
        byte lastchunck[]=new byte[s.length()%31];
        int j=0;
        for(int i=0;i<chuncked[0].length;i++){
            if(chuncked[chuncked.length-1][i]!=(byte)0){
               lastchunck[j]=(byte)(chuncked[chuncked.length-1][i]);
               j++;
             }
        }
        // convert to int!
        int[] chuncks=new int[chuncked.length];
        for(int w=0;w<chuncks.length-1;w++){
            chuncks[w]=new int(chuncked[w]);
            //System.out.print(new String(chuncks[w].toByteArray()));
        }
        //convert last chunk
        chuncks[chuncks.length-1]=new int(lastchunck);
       // System.out.println(new String(chuncks[chuncks.length-1].toByteArray()));
        //encrypt
        cipherT=encrypt(new Elgamal_PlainText(chuncks));
        return cipherT;
    }
    public Elgamal_PlainText decrypt(Elgamal_CipherText ct){
        Elgamal_PlainText pt;
        int mod=kset.getPk().getP();
        int tmp;
        int plain[]=new int[ct.getCt().length];
        for(int i=0;i<plain.length;i++){
            tmp=ct.getGr().modPow(kset.getSk().getX(), mod);
            plain[i]=ct.getCt()[i].multiply(tmp.modInverse(mod)).mod(mod);
        }
        //int s=ct.getGr().modPow(kset.getSk().getX(), kset.getPk().getP());
        //int decrypt=ct.getCt().multiply(s.modInverse(kset.getPk().getP())).mod(kset.getPk().getP());
        pt=new Elgamal_PlainText(plain);
        return pt;
    }
    public static byte[][] divideArray(byte[] source, int chunksize) {
        byte[][] ret = new byte[(int)Math.ceil(source.length / (double)chunksize)][chunksize];
        int start = 0;
        for(int i = 0; i < ret.length; i++) {
            ret[i] = Arrays.copyOfRange(source,start, start + chunksize);
            start += chunksize ;
        }
        return ret;
    }
    public String Elgamal_PtToString(Elgamal_PlainText pt){
        String res="";
        for(int i=0;i<pt.getPt().length;i++){
            res+=new String(pt.getPt()[i].toByteArray());
        }
        return res;
    }
    public static ArrayList<int> ordre(int p){
        int factor1=new int("2");
        ArrayList<int> list = new ArrayList<int>();
        int factor2=(p.subtract(int.ONE)).divide(factor1);
        list.add(null);
        System.out.println("here  "+factor1+"  "+factor2);
        int i=int.ONE;
        int ordre;
        boolean found=false;
        while(i.compareTo(p)==-1){
            if(i.mod(factor1)==int.ZERO ||i.mod(factor2)==int.ZERO){
                list.add(null);
            }else{
                ordre=int.ONE;
                found=false;
                while(!found){
                    if(i.modPow(ordre,p).compareTo(int.ONE)==0){
                        found=true;
                        list.add(ordre);
                    }else{
                        ordre=ordre.add(int.ONE);
                    }
                }
            }     
            i=i.add(int.ONE);
        }
        return list;
    }
    
}
