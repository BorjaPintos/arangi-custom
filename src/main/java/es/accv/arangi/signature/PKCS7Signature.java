/**
 * LICENCIA LGPL:
 * 
 * Esta librer�a es Software Libre; Usted puede redistribuirla y/o modificarla
 * bajo los t�rminos de la GNU Lesser General Public License (LGPL) tal y como 
 * ha sido publicada por la Free Software Foundation; o bien la versi�n 2.1 de 
 * la Licencia, o (a su elecci�n) cualquier versi�n posterior.
 * 
 * Esta librer�a se distribuye con la esperanza de que sea �til, pero SIN 
 * NINGUNA GARANT�A; tampoco las impl�citas garant�as de MERCANTILIDAD o 
 * ADECUACI�N A UN PROP�SITO PARTICULAR. Consulte la GNU Lesser General Public 
 * License (LGPL) para m�s detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL) 
 * junto con esta librer�a; si no es as�, escriba a la Free Software Foundation 
 * Inc. 51 Franklin Street, 5� Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011 Agencia de Tecnolog�a y Certificaci�n Electr�nica
 */
package es.accv.arangi.signature;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;

import org.apache.log4j.Logger;

import es.accv.arangi.base.algorithm.DigitalSignatureAlgorithm;
import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.NoDocumentToSignException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.device.ACCVDeviceManager;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase que representa una firma en formato PKCS#7.<br><br>
 * 
 * Esta clase simplifica la funcionalidad de su clase padre al utilizar un algoritmo
 * de firma fijo (SHA1WithRSA), no permitir generar firmas attached y validar s�lo 
 * los certificados tratados por Arang�. Es capaz de validar firmas tanto attached 
 * como detached. 
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class PKCS7Signature extends es.accv.arangi.base.signature.PKCS7Signature {

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(PKCS7Signature.class);
	
	/**
	 * Obtiene la firma de un stream de lectura.
	 * 
	 * @param isSignature Stream de lectura a la firma en formato PKCS#7
	 * @throws IOException Error leyendo el stream de lectura o la firma proporcionada no parece 
	 * 	estar en formato DER
	 * @throws NormalizeCertificateException El certificado de la firma no puede ser normalizado
	 * 	al formato esperado por el proveedor criptogr�fico de Arangi
	 * @throws SignatureException Error construyendo la firma
	 */
	public PKCS7Signature(InputStream isSignature) throws NormalizeCertificateException, SignatureException, IOException {
		super(isSignature);
	}

	
	/**
	 * Obtiene la firma de un fichero.
	 * 
	 * @param fileSignature Fichero con la firma en formato PKCS#7
	 * @throws IOException Error leyendo el fichero o la firma proporcionada no parece estar en formato DER
	 * @throws NormalizeCertificateException El certificado de la firma no puede ser normalizado
	 * 	al formato esperado por el proveedor criptogr�fico de Arangi
	 * @throws SignatureException Error construyendo la firma
	 */
	public PKCS7Signature(File fileSignature) throws NormalizeCertificateException, SignatureException, IOException {
		super(fileSignature);
	}

	/**
	 * Obtiene la firma de un array de bytes.
	 * 
	 * @param signature Firma en formato PKCS#7
	 * @throws NormalizeCertificateException El certificado de la firma no puede ser normalizado
	 * 	al formato esperado por el proveedor criptogr�fico de Arangi
	 * @throws SignatureException Error construyendo la firma
	 */
	public PKCS7Signature(byte[] signature) throws NormalizeCertificateException, SignatureException {
		super(signature);
	}
	
	/**
	 * Construye una firma en formato PKCS#7 en base a los bytes de las firmas y
	 * los certificados con los que se realizaron �stas.
	 * 
	 * @param signatureBytes Bytes de las firmas
	 * @param certificates Certificados con los que se realiz� la firma
	 * @throws SignatureException Error construyendo la firma
	 */
	public PKCS7Signature(byte[][] signatureBytes, Certificate[] certificates)
			throws SignatureException {
		super(signatureBytes, certificates);
	}
	
	/**
	 * Obtiene un objeto {@link PKCS7Signature PKCS7Signature} al firmar el documento con los
	 * dispositivos pasados como par�metro (m�s de un dispositivo ocasionar� una firma
	 * m�ltiple). Siempre realiza una firma detached.
	 * 
	 * @param managers Dispositivos criptogr�ficos
	 * @param document Documento a firmar
	 * @throws HashingException No es posible obtener el hash del documento o su versi�n en 
	 * 	formato DER durante el proceso de firma
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws SignatureException Error durante el proceso de firma
	 * @throws NormalizeCertificateException El certificado de la firma no puede ser normalizado
	 * 	al formato esperado por el proveedor criptogr�fico de Arangi
	 */
	public static PKCS7Signature sign (ACCVDeviceManager[] managers, IDocument document) throws HashingException, LoadingObjectException, SignatureException, NormalizeCertificateException {
		logger.debug ("[CMSSignature.sign]::Entrada::" + Arrays.asList(new Object[] { managers, document } ));
		
		return PKCS7Signature.sign(managers, document, false);
	}
	
	/**
	 * Obtiene un objeto {@link PKCS7Signature PKCS7Signature} al firmar el documento con los
	 * dispositivos pasados como par�metro (m�s de un dispositivo ocasionar� una firma
	 * m�ltiple).
	 * 
	 * @param managers Dispositivos criptogr�ficos
	 * @param document Documento a firmar
	 * @param isAttached Atached o detached
	 * @throws HashingException No es posible obtener el hash del documento o su versi�n en 
	 * 	formato DER durante el proceso de firma
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws SignatureException Error durante el proceso de firma
	 * @throws NormalizeCertificateException El certificado de la firma no puede ser normalizado
	 * 	al formato esperado por el proveedor criptogr�fico de Arangi
	 */
	public static PKCS7Signature sign (ACCVDeviceManager[] managers, IDocument document, boolean isAttached) throws HashingException, LoadingObjectException, SignatureException, NormalizeCertificateException {
		logger.debug ("[CMSSignature.sign]::Entrada::" + Arrays.asList(new Object[] { managers, document, isAttached } ));
		
		//-- Obtener la lista de bytes de firma y certificados con los que se realizan
		ArrayList alSignatureBytes = new ArrayList ();
		Certificate [] certificates = new Certificate [managers.length];
		String [] algorithms = new String [managers.length];
		for (int i = 0; i < managers.length; i++) {
			//-- Obtener la firma
			alSignatureBytes.add(managers[i].signDocument(document));
			
			//-- A�adir algoritmo (SHA1WithRSA)
			algorithms[i] = DigitalSignatureAlgorithm.SHA1_RSA;
			
			//-- Obtener el certificado
			try {
				certificates[i] = new Certificate (managers[i].getSignatureCertificate());
			} catch (NormalizeCertificateException e) {
				logger.info("[CMSSignature.sign]::El certificado de la firma no ha podido ser normalizado a un formato reconocido " +
						"por el proveedor criptogr�fico de Arangi ", e);
				throw new SignatureException ("El certificado de la firma no ha podido ser normalizado a un formato reconocido por el " +
						"proveedor criptogr�fico de Arangi ", e);
			}
		}
		byte[][] signaturesBytes = (byte[][])alSignatureBytes.toArray(new byte[0][0]);
		
		//-- Obtener la firma CMS
		byte[] pk7Signature;
		if (isAttached) {
			pk7Signature = createPKCS7CMS (signaturesBytes, certificates, document, algorithms, OID_FORMATO_FIRMA);
		} else {
			pk7Signature = createPKCS7CMS (signaturesBytes, certificates, null, algorithms, OID_FORMATO_FIRMA);
		}
		
		//-- Obtener el objeto
		return new PKCS7Signature (pk7Signature);
	}

	/**
	 * Comprueba que las firmas son correctas en firmas attached y sus certificados son v�lidos. S�lo
	 * ser�n validados los certificados tratados por Arang�.<br><br>
	 * 
	 * Sobre la validaci�n de certificados hay que tener en cuenta:<br>
	 * <ul>
	 * 	<li>Si existe un sello de tiempos, �ste s�lo ser� �til mientras el certificado 
	 *  no caduque. Despu�s, al ser imposible obtener la informaci�n de revocaci�n
	 *  para este certificado, este m�todo devolver� siempre un resultado falso aunque el 
	 *  certificado fuera v�lido cuando se gener� la firma .</li>
	 * 	<li>Si la firma incluye informaci�n de revocaci�n (CRLs o respuestas OCSP) �sta 
	 * 	si que se tendr� en cuenta aunque el certificado haya caducado: concepto de
	 * 	firma longeva</li>
	 * </ul><br><br>
	 * 
	 * IMPORTANTE: este m�todo s�lo puede ser utilizado si la firma es attached (el documento
	 * que origin� la firma se incluye en �sta). Si no es as� utilizar el m�todo con el mismo nombre 
	 * pero con el documento que origin� la firma como par�metro.
	 * 
	 * @return Para cada certificado el resultado de comprobar si la firma es correcta y el certificado es
	 * 	v�lido
	 * @throws SignatureException Error tratando el objeto firma
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arang� o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws NoDocumentToSignException La firma no es attached por lo que no hay documento con
	 * 	el que validarla. Utilizar este mismo m�todo pero pas�ndole el documento que origin� la
	 * 	firma
	 */
	public ValidationResult[] isValid() throws HashingException, SignatureException, NormalizeCertificateException,
			NoDocumentToSignException {
		return super.isValid(ArangiUtil.getACCVCaList());
	}
	
	/**
	 * Comprueba que las firmas son correctas y sus certificados son v�lidos. S�lo
	 * ser�n validados los certificados tratados por Arang�.<br><br> 
	 * 
	 * Sobre la validaci�n de certificados hay que tener en cuenta:<br>
	 * <ul>
	 * 	<li>Si existe un sello de tiempos, �ste s�lo ser� �til mientras el certificado 
	 *  no caduque. Despu�s, al ser imposible obtener la informaci�n de revocaci�n
	 *  para este certificado, este m�todo devolver� siempre un resultado falso aunque el 
	 *  certificado fuera v�lido cuando se gener� la firma .</li>
	 * 	<li>Si la firma incluye informaci�n de revocaci�n (CRLs o respuestas OCSP) �sta 
	 * 	si que se tendr� en cuenta aunque el certificado haya caducado: concepto de
	 * 	firma longeva</li>
	 * </ul>
	 * 
	 * @param document documento firmado en el PKCS7.
	 * @return Para cada certificado resultado de comprobar si la firma es correcta y el certificado es
	 * 	v�lido
	 * @throws SignatureException Error tratando el objeto firma
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arangi o su 
	 * 	firma no es correcta o no puede ser analizada
	 */
	public ValidationResult[] isValid (IDocument document) throws HashingException, SignatureException, NormalizeCertificateException {
		return super.isValid(document, ArangiUtil.getACCVCaList());
	}

}
