package rsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class DigitalSignature {
	

	byte[] digest, msg1, msg2;
	BigInteger digestBigInt;
	KeyGen keyGenerator;
	
	List<BigInteger> properKey;
	
	public byte[] appendArray(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
	
	public byte[] removeLeadingZeroes(byte[] arr){
		int count = 0;

        for(int i = 0; i < arr.length ; i++)
        {

            if(arr[i]!=0){ 
                break;
            }
            count++;
        }
        byte [] output = new byte[arr.length-count];
        for(int i = 0; i<(arr.length-count);i++) {
            output[i] = arr[i+count];
        }
        return output; 
	}
	
	//Converts the byte-array digest into a big int, using the generated key to create the new big int.
	public BigInteger digestToBigInt(byte[] md){
		BigInteger bg = new BigInteger(1, md);
		
		//Create the cipher that will be passes to the receiver. The cipher is represented in big int.	
		
		bg = bg.modPow(properKey.get(0), properKey.get(1));
		return bg;
	}
	
	public byte[] bigIntToDigest(BigInteger signature){
		//Take the signature from the sender and reverse the Big Integer back into a byte array (digest)
		BigInteger invBg = signature.modPow(properKey.get(0), properKey.get(1));
		byte[] digest = invBg.toByteArray();
		
		return digest;
	}
	
	public void signMessageToFile(byte[] msg, BigInteger digInt){
		try(
				OutputStream os = new FileOutputStream("message.txt.signed");
				ObjectOutputStream oos = new ObjectOutputStream(os);){
				//The big integer digest of the sent message.
				oos.writeObject(digInt);
				//The actual message.
				os.write(msg);
				os.flush();
				os.close();
			}
			catch(Exception e){
				e.printStackTrace();
			}
	}
	
	public void sender(File plaintext) throws NoSuchAlgorithmException{
		
		keyGenerator = new KeyGen();
		MessageDigest md = MessageDigest.getInstance("MD5");
		
		try(FileInputStream in = new FileInputStream(plaintext);){
			int readByte;
			byte[] msg = new byte[0];
			
			//read the text file byte-by-byte...Append each new byte to for the full message.
			while((readByte = in.read()) != -1){
				byte[] msgByte = {(byte) readByte};
				msg = appendArray(msg, msgByte);
			}
			String strMsg = new String(msg);
			msg1 = strMsg.getBytes();
			
			//Update the md5 with the byte message.
			md.update(msg1);
			digest = md.digest();
			
			//Get a key and prepend it to the digest.
			properKey = keyGenerator.readKeyFile("privkey.rsa");
			if(properKey.isEmpty()){
				System.out.println("Function now exiting...");
			}
			else{
				//Get a bigInteger value derived from the message digest.
				digestBigInt = digestToBigInt(digest);
				
				//Sign the bigInt digest to file.
				signMessageToFile(msg, digestBigInt);
			}
			
		}catch(Exception e){
			System.out.println("There was a problem signing the message!");
		}
		
	}
	
	public void receiver(File signature) throws NoSuchAlgorithmException{
		
		keyGenerator = new KeyGen();
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] revDigest;
		
		try(InputStream in = new FileInputStream(signature);
			ObjectInputStream ois = new ObjectInputStream(in);){
			
			BigInteger sig;
			
			byte[] msg = new byte[0];
			int readByte;
			
			sig = (BigInteger) ois.readObject();
			while((readByte = in.read()) != -1){
				byte[] msgByte = {(byte) readByte};
				//System.out.println((byte) readByte);
				msg = appendArray(msg, msgByte);
			}
			String strMsg = new String(msg);
			msg2 = strMsg.getBytes();

			in.close();
			//Get a key and prepend it to the digest.
			properKey = keyGenerator.readKeyFile("pubkey.rsa");
			
			if(properKey.isEmpty()){
				System.out.println("Function now exiting...");
			}
			else{
				//Reverse the signature to get the digest. Then remove the leading zeroes from the conversion...
				revDigest = bigIntToDigest(sig);
				byte[] revisedRevDigest = removeLeadingZeroes(revDigest);
				
				//Update the md5 with the byte message.
				md.update(msg2);

				byte[] digest = md.digest();
				System.out.println("The message received is " + (MessageDigest.isEqual(digest, revisedRevDigest)? "valid!": "invalid!"));
			}
		}
		catch(Exception e){
			System.out.println("The file does not exist or it cannot be read!");
		}
	}
	
	public static void main(String args[]) throws NoSuchAlgorithmException{
	}


}
