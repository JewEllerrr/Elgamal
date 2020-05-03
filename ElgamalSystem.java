import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Vector;

import org.apache.commons.codec.digest.DigestUtils;

public class ElgamalSystem {

	private BigInteger p;
	private BigInteger g;
	private BigInteger y;
	private BigInteger m = BigInteger.ZERO;

	private BigInteger x;
	private BigInteger crypto_k;
	private BigInteger k_signature;

	private Vector<BigInteger> a = new Vector<BigInteger>();
	private Vector<BigInteger> b = new Vector<BigInteger>();
	private BigInteger r;
	private BigInteger s;

	private Random random = new Random();
	private int lenKey = 0;

	public ElgamalSystem() {

	}

	public ElgamalSystem(int len) {
		try {
			if (len < 128)
				throw new Exception("Key length can't be less than 128 bit");
			else {
				lenKey = len;
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
			System.exit(0);
		}
	}

	private void GeneratingKey() {
		boolean[] arrForP = null;
		boolean[] arrForG = null;
		boolean[] arrForX = null;
		if (lenKey >= 128) {
			arrForP = new boolean[lenKey];
			arrForG = new boolean[lenKey / 2];
			arrForX = new boolean[lenKey];
		} else {
			lenKey = 128 + (int) (Math.random() * 897);
			arrForP = new boolean[lenKey];
			arrForG = new boolean[lenKey / 2];
			arrForX = new boolean[lenKey];
		}
		if (m.compareTo(BigInteger.ZERO) != 0) {
			do {
				p = RandomGeneration(arrForP);
			} while (!p.isProbablePrime(100) || p.compareTo(m) < 0);
			System.out.println("M: " + m);
		} else {
			do {
				p = RandomGeneration(arrForP);
			} while (!p.isProbablePrime(100));
		}
		System.out.println("p: " + p);

		do {
			g = RandomGeneration(arrForG);
		} while (gcd(g, p).compareTo(BigInteger.ONE) != 0 || g.compareTo(p) >= 0);
		System.out.println("g: " + g);

		do {
			x = RandomGeneration(arrForX);
		} while (gcd(x, p).compareTo(BigInteger.ONE) != 0 || x.compareTo(p) >= 0);

		y = g.modPow(x, p);
		System.out.println("y: " + y);
	}

	public void MessageSignature(String message) {
		m = getBigIntegerHeshMD5(message);
		GeneratingKey();
		boolean[] arrForK = new boolean[lenKey];
		do {
			k_signature = RandomGeneration(arrForK);
		} while (gcd(p.subtract(BigInteger.ONE), k_signature).compareTo(BigInteger.ONE) != 0
				|| k_signature.compareTo(p.subtract(BigInteger.ONE)) >= 0);
		System.out.println("k: " + k_signature);

		r = g.modPow(k_signature, p);

		// s = (m-xr)*k^-1 (mod p-1)
		BigInteger m_xr = m.subtract(x.multiply(r)).mod(p.subtract(BigInteger.ONE));
		BigInteger k_inv = inverseElement(k_signature, p.subtract(BigInteger.ONE));
		System.out.println("k_inv: " + k_inv);
		
		s = m_xr.multiply(k_inv).mod(p.subtract(BigInteger.ONE));
	}

	public void SignatureVerification(String message, BigInteger[] keys) {
		BigInteger p = keys[0];
		BigInteger g = keys[1];
		BigInteger y = keys[2];
		BigInteger r = keys[3];
		BigInteger s = keys[4];
		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(p) >= 0) {
			System.out.println("Signature is not correct");
		}
		m = getBigIntegerHeshMD5(message);
		BigInteger y_r = y.modPow(r, p);
		BigInteger r_s = r.modPow(s, p);
		BigInteger y_r_s = y_r.multiply(r_s);
		y_r_s = y_r_s.mod(p);
		System.out.println("y_r_s: " + y_r_s);
		BigInteger g_m = g.modPow(m, p);
		System.out.println("  g_m: " + g_m);
		if (y_r_s.compareTo(g_m) == 0) {
			System.out.println("Signature is correct");
		} else
			System.out.println("Signature is NOT correct");
	}

	public void Encryption(String message, BigInteger[] keys) {
		BigInteger lenkey = keys[0];
		BigInteger p = keys[1];
		BigInteger g = keys[2];
		BigInteger y = keys[3];
		boolean[] arrForK = new boolean[lenkey.intValue()];
		do {
			crypto_k = RandomGeneration(arrForK);
		} while (crypto_k.compareTo(p.subtract(BigInteger.ONE)) >= 0);
		try (FileInputStream fileIn = new FileInputStream(message)) {
			int c;
			while (fileIn.available() > 0) {
				c = fileIn.read();
				m = BigInteger.valueOf(c);
				a.add(g.modPow(crypto_k, p));
				b.add(y.modPow(crypto_k, p).multiply(m).mod(p));
			}
			fileIn.close();
		} catch (IOException ex) {
			System.out.println(ex.getMessage());
		}
		System.out.println("Encryption done");
	}

	public void Decryption(Vector<Vector<BigInteger>> keys) {
		Vector<BigInteger> a = keys.get(0);
		Vector<BigInteger> b = keys.get(1);
		BigInteger a_tmp;
		BigInteger res;
		try (FileOutputStream fileOut = new FileOutputStream("result.txt")) {
			for (int i = 0; i < a.size(); i++) {
				a_tmp = a.get(i).modPow(p.subtract(BigInteger.ONE).subtract(this.x), p);
				res = b.get(i).multiply(a_tmp).mod(p);
				fileOut.write(res.intValue());
			}
			fileOut.close();
		} catch (IOException ex) {
			System.out.println(ex.getMessage());
		}
		System.out.println("Decryption done");
	}
	
	////////////////////////////////Math functions///////////////////////////////////

	private BigInteger inverseElement(BigInteger a, BigInteger b) {
		BigInteger x[] = new BigInteger[2];
		BigInteger y[] = new BigInteger[2];
		BigInteger q, r, xx, yy;
		int sign = 1;
		BigInteger bCopy = b;

		// initializes the coefficients
		x[0] = BigInteger.ONE;
		x[1] = BigInteger.ZERO;
		y[0] = BigInteger.ZERO;
		y[1] = BigInteger.ONE;

		// As long as b != 0 we replace a by b and b by a % b.
		while (!b.equals(BigInteger.ZERO)) {
			r = a.mod(b);
			q = a.divide(b);
			a = b;
			b = r;
			xx = x[1];
			yy = y[1];
			x[1] = (q.multiply(x[1])).add(x[0]);
			y[1] = (q.multiply(y[1])).add(y[0]);
			x[0] = xx;
			y[0] = yy;
			sign = -sign;
		}
		// Final computation of the coefficients
		x[0] = x[0].multiply(new BigInteger(String.valueOf(sign)));
		y[0] = y[0].multiply(new BigInteger(String.valueOf(-sign)));

		if (x[0].compareTo(BigInteger.ZERO) < 0) { // less than 0
			return bCopy.add(x[0]);
		} else { // equal or greater than 0
			return x[0];
		}
	}
	
	private BigInteger binpow(BigInteger a, int n) {
		BigInteger res = new BigInteger("1");
		while (n != 0) {
			if ((n & 1) != 0) {
				res = res.multiply(a);
			}
			a = a.multiply(a);
			n >>= 1;
		}
		return res;
	}

	private BigInteger gcd(BigInteger a, BigInteger b) {
		if (b.compareTo(BigInteger.ZERO) == 0)
			return a;
		else
			return gcd(b, a.mod(b));
	}
	
	////////////////////////////////////Helper functions/////////////////////////////

	private BigInteger RandomGeneration(boolean[] arr) {
		for (int i = 0; i < arr.length; i++) {
			arr[i] = random.nextBoolean();
		}
		BigInteger num = new BigInteger("0");
		for (int i = arr.length - 1; i >= 0; i--) {
			if (arr[i] == true) {
				num = num.add(binpow(BigInteger.TWO, i));
			}
		}
		return num;
	}

	private BigInteger getBigIntegerHeshMD5(String pathToFile) {
		//this function gets hash from file
		Path testFilePath = Paths.get(pathToFile);
		byte[] fileContent = null;
		try {
			fileContent = Files.readAllBytes(testFilePath);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(404);
		}
		String digits = "0123456789ABCDEF";
		String hash = DigestUtils.md5Hex(fileContent);
		hash = hash.toUpperCase();
		BigInteger val = BigInteger.valueOf(0);
		BigInteger sixteen = BigInteger.valueOf(16);
		for (int i = 0; i < hash.length(); i++) {
			char c = hash.charAt(i);
			int d = digits.indexOf(c);
			BigInteger b = BigInteger.valueOf(d);
			val = val.multiply(sixteen);
			val = val.add(b);
		}
		return val;
	}

	public BigInteger[] getKeysForVerificationMessage() {
		BigInteger keys[] = new BigInteger[5];
		keys[0] = getP();
		keys[1] = getG();
		keys[2] = getY();
		keys[3] = getR();
		keys[4] = getS();
		return keys;
	}

	public BigInteger[] getOpenKeysForEncryption() {
		m = BigInteger.ZERO;
		GeneratingKey();
		BigInteger keys[] = new BigInteger[4];
		keys[0] = BigInteger.valueOf(getLenKey());
		keys[1] = getP();
		keys[2] = getG();
		keys[3] = getY();
		return keys;
	}

	public Vector<Vector<BigInteger>> getCipherText() {
		Vector<Vector<BigInteger>> keys = new Vector<Vector<BigInteger>>();
		keys.add(getA());
		keys.add(getB());
		return keys;
	}

	public Vector<BigInteger> getA() {
		return a;
	}
	public Vector<BigInteger> getB() {
		return b;
	}
	

	public BigInteger getP() {
		return p;
	}

	public BigInteger getG() {
		return g;
	}

	public BigInteger getY() {
		return y;
	}

	public BigInteger getR() {
		return r;
	}

	public BigInteger getS() {
		return s;
	}

	public int getLenKey() {
		return lenKey;
	}

}