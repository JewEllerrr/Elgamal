
public class Main {

	public static void main(String[] args) {
		ElgamalSystem Alice = new ElgamalSystem(128);
		ElgamalSystem Bob = new ElgamalSystem(256);
		String pathToFile = "C:\\Users\\????\\kek.txt";
		
		System.out.println("Message Signature Mode:");
		Alice.MessageSignature(pathToFile);
		Bob.SignatureVerification(pathToFile, Alice.getKeysForVerificationMessage());
		
		System.out.println("Encryption Mode:");
		Alice.Encryption(pathToFile, Bob.getOpenKeysForEncryption());
		Bob.Decryption(Alice.getCipherText());
	}
}
