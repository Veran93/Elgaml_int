package elgamal;



/**
 *
 * @author oorestisime
 */
public class Elgamal_SecretKey {
   private int p;
   private int x;
   
   public Elgamal_SecretKey(int p,int x){
     this.p=p;
     this.x=x;
   }

    /**
     * @return the p
     */
    public int getP() {
        return p;
    }

    /**
     * @return the x
     */
    public int getX() {
        return x;
    }
   
}
