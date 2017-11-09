package rsa;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class KeyGen {

	private BigInteger primeP;  			// p
	private BigInteger primeQ; 				// q
	private BigInteger keyProduct; 			// n
	private BigInteger totient;    			// totient(n)
	private BigInteger relativePrime; 		// also known as e, gcd(relativePrime, totient) = 1
	private BigInteger d;					// d = e^(-1) mod totient
	
	public KeyGen(){
		primeP = BigInteger.probablePrime(512, new Random());
		primeQ = BigInteger.probablePrime(512, new Random());
		
		while(primeP.equals(primeQ)){
			primeQ = BigInteger.probablePrime(512, new Random());
		}
		
		// n = p x q
		keyProduct = primeP.multiply(primeQ);
		
		// totient(n) = (p-1) x (q-1)
		totient = (primeP.subtract(BigInteger.ONE)).multiply(primeQ.subtract(BigInteger.ONE));
		
		// e, gcd(relativePrime, totient) = 1
		relativePrime  = BigInteger.probablePrime(512, new Random());
		while(true){
			if(!relativePrime.equals(primeP) && !relativePrime.equals(primeQ) && (relativePrime.gcd(totient)).equals(BigInteger.ONE)){
				break;
			}
			relativePrime  = BigInteger.probablePrime(512, new Random());
		}
		
		// d = e^(-1) mod totient
		d = relativePrime.modInverse(totient);
	}
	
	public BigInteger getPrimeP() {
		return primeP;
	}

	public BigInteger getPrimeQ() {
		return primeQ;
	}

	public BigInteger getKeyProduct() {
		return keyProduct;
	}

	public BigInteger getTotient() {
		return totient;
	}

	public BigInteger getRelativePrime() {
		return relativePrime;
	}

	public BigInteger getD() {
		return d;
	}

	public List<BigInteger> getPublic(){
		// public key = < relativePrime, totient >
		List<BigInteger> publicKey = new ArrayList<BigInteger>();
		
		publicKey.add(relativePrime);
		publicKey.add(keyProduct);
		
		return publicKey;
	}
	
	public List<BigInteger> getPrivate(){
		// private key = < d, totient >
		List<BigInteger> privateKey = new ArrayList<BigInteger>();
		
		privateKey.add(d);
		privateKey.add(keyProduct);
		
		return privateKey;
	}
	
	public void publicKeyToFile(){
		try(OutputStream os = new FileOutputStream("pubkey.rsa");
			ObjectOutputStream oos = new ObjectOutputStream(os);){
			oos.writeObject(this.getRelativePrime());
			oos.writeObject(this.getKeyProduct());
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}

	public void privateKeyToFile(){
		try(OutputStream os = new FileOutputStream("privkey.rsa");
			ObjectOutputStream oos = new ObjectOutputStream(os);){
			oos.writeObject(this.getD());
			oos.writeObject(this.getKeyProduct());
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public List<BigInteger> readKeyFile(String file){
		List<BigInteger> keys = new ArrayList<BigInteger>();
		try(InputStream is = new FileInputStream(file);
			ObjectInputStream ois = new ObjectInputStream(is);){
			
			keys.add( (BigInteger) ois.readObject()  );
			keys.add( (BigInteger) ois.readObject()  );
			
		}
		catch(Exception e){
			System.out.println("Cannot perform the function without a key!");
		}
		
		return keys;
	}
	
	public static void main(String[] args){
		KeyGen keyGen = new KeyGen();
		System.out.println("P: " + keyGen.getPrimeP());
		System.out.println("P is prime: " + keyGen.getPrimeP().isProbablePrime(500)+ "\n");
		
		System.out.println("Q: " + keyGen.getPrimeQ());
		System.out.println("Q is prime: " + keyGen.getPrimeQ().isProbablePrime(500)+ "\n");
		
		System.out.println("E: " + keyGen.getRelativePrime());
		System.out.println("E is prime: " + keyGen.getRelativePrime().isProbablePrime(500)+ "\n");

		System.out.println("D: " + keyGen.getD());

		System.out.println("N: " + keyGen.getKeyProduct());
		
		keyGen.publicKeyToFile();
		keyGen.privateKeyToFile();
		
		// Check if they're the same
		System.out.println("=======================================================");
		
		List<BigInteger> publicKey = keyGen.readKeyFile("pubkey.rsa");
		List<BigInteger> privateKey = keyGen.readKeyFile("privkey.rsa");
		
		System.out.println("Comparing public E: " + publicKey.get(0).equals(keyGen.getRelativePrime()));
		System.out.println("Comparing public N: " + publicKey.get(1).equals(keyGen.getKeyProduct()));
		
		System.out.println();		
		System.out.println("Comparing private D: " + privateKey.get(0).equals(keyGen.getD()));
		System.out.println("Comparing private N: " + privateKey.get(1).equals(keyGen.getKeyProduct()));
	}

}
