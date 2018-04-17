/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirla y/o modificarla
 * bajo los términos de la GNU Lesser General Public License (LGPL) tal y como 
 * ha sido publicada por la Free Software Foundation; o bien la versión 2.1 de 
 * la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN 
 * NINGUNA GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o 
 * ADECUACIÓN A UN PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public 
 * License (LGPL) para más detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL) 
 * junto con esta librería; si no es así, escriba a la Free Software Foundation 
 * Inc. 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011 Agencia de Tecnología y Certificación Electrónica
 */
package es.accv.arangi.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;

import javax.activation.DataSource;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.SharedByteArrayInputStream;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.encoders.Hex;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.certificate.validation.CertificateOCSPResponse;
import es.accv.arangi.base.certificate.validation.CertificateValidationService;
import es.accv.arangi.base.certificate.validation.OCSPResponse;
import es.accv.arangi.base.document.ByteArrayDocument;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.validation.MalformedOCSPResponseException;
import es.accv.arangi.base.exception.certificate.validation.ServiceException;
import es.accv.arangi.base.exception.certificate.validation.ServiceNotFoundException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.NoDocumentToSignException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.exception.timestamp.MalformedTimeStampException;
import es.accv.arangi.base.signature.ISignature;
import es.accv.arangi.base.signature.Signature;
import es.accv.arangi.base.util.Util;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.exception.signature.ACCVWebServicesConnectionException;
import es.accv.arangi.exception.signature.MalformedTokenException;
import es.accv.arangi.timestamp.TimeStamp;
import es.accv.arangi.util.smime.SMIMESigned;

/**
 * Clase para el tratamiento de los tokens de validación de la ACCV. Estos tokens se
 * generan y validan mediante llamadas a los servicios web de la ACCV, por lo que
 * estas acciones requieren que la URL de los servicios web sea accesible desde donde
 * se esté ejecutando esta clase. Además, si va a utilizar los servicios web de test, 
 * necesitará que desde la ACCV le abran los puertos para poder acceder.<br><br>
 * 
 * El token de validación de la ACCV es un formato de firma longeva, ya que contiene,
 * además de la firma del documento, un sello de tiempos y la respuesta OCSP que 
 * garantizan que el certificado era válido en el momento de producirse la generación
 * del token. Además toda esta información viene firmada por la propia ACCV.<br><br>
 * 
 * El token de validación de la ACCV es un S/MIME firmado que los servicios web de la 
 * ACCV devuelven en formato base64.  
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class ACCVValidationToken extends Signature {
	
	/*
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(ACCVValidationToken.class);
	
	/**
	 * URL de los servicios web de la ACCV: http://webserv.pki.gva.es:8080/axis/services/serviciospki
	 */
	public static final String URL_ACCV_WEBSERVICES 		= "http://webserv.pki.gva.es:8080/axis/services/serviciospki";
	
	/**
	 * URL de los servicios web de la ACCV: http://sleipnir2.pki.gva.es:8084/axis/services/serviciospki
	 */
	public static final String URL_ACCV_WEBSERVICES_TEST 	= "http://sleipnir2.pki.gva.es:8084/axis/services/serviciospki";
	
	/*
	 * Formateador de la fecha para el XML de validacion
	 */
	public static SimpleDateFormat VALIDATION_XML_DATE_FORMAT = new SimpleDateFormat ("yyyyMMddHHmmssz");
	
	/*
	 * Mensaje SMIME
	 */
	private MimeMessage token;
	
	/*
	 * Contenido en base64
	 */
	private byte[] tokenB64;
	
	/*
	 * Firma PKCS#7
	 */
	private PKCS7Signature pkcs7Signature;
	
	/*
	 * Firma PKCS#7 del token
	 */
	private PKCS7Signature tokenSignature;
	
	/*
	 * Sello de tiempos
	 */
	private TimeStamp timeStamp;
	
	/*
	 * Respuesta OCSP
	 */
	private OCSPResponse ocspResponse;
	
	/*
	 * Sello de tiempos de archivo
	 */
	private TimeStamp archiveTimeStamp;
	
	/*
	 * Respuesta OCSP del certificado de sello de tiempos
	 */
	private OCSPResponse tsCertificateOcspResponse;
	
	static {
		//-- La fecha del xml de validación se mostrará como si estuviésemos en la zona
		//-- horaria GMT0
		VALIDATION_XML_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("Etc/GMT+0"));
		
		//-- Añadir esta clase a la lista de clases reconocedoras de firma
		addClassToSignatureValidation();
	}
	
	//-- Constructores
	
	/**
	* Crea un Token de la Autoridad de Validación de la ACCV cargándolo desde un array de bytes
	* (contendrá el token en formato base64). 
	* 
	* @param bytesToken Array de bytes con el contenido del token
	* @throws MalformedTokenException El token no está correctamente formado
	*/
	public ACCVValidationToken(byte[] bytesToken) throws MalformedTokenException {
		initialize(bytesToken);
	}

	/**
	* Crea un Token de la Autoridad de Validación de la ACCV a partir de un fichero 
	* (contendrá el token en formato base64). 
	* 
	* @param fileToken Fichero con el contenido del token
	* @throws MalformedTokenException El token no está correctamente formado
	* @throws FileNotFoundException  El fichero no existe o no se puede leer
	*/
	public ACCVValidationToken(File fileToken) throws MalformedTokenException, FileNotFoundException {
		try {
			initialize (Util.loadFile(fileToken));
		} catch (IOException e) {
			logger.info ("[ACCVValidationToken]::El fichero no existe o no se puede leer", e);
			throw new FileNotFoundException ("El fichero no existe o no se puede leer");
		}
	}

	/**
	* Crea un Token de la Autoridad de Validación de la ACCV a partir de un stream
	* de lectura (contendrá el token en formato base64). 
	* 
	* @param isToken Stream de lectura que apunta al contenido del token
	* @throws MalformedTokenException El token no está correctamente formado
	*/
	public ACCVValidationToken(InputStream isToken) throws MalformedTokenException {
		try {
			initialize(Util.readStream(isToken));
		} catch (IOException e) {
			logger.info ("[ACCVValidationToken]::Ha ocurrido un error leyendo el stream de lectura", e);
			throw new MalformedTokenException ("Ha ocurrido un error leyendo el stream de lectura", e);
		}
	}
	
	/**
	 * Obtiene un token de validación conectándose a los servicios web de explotación de 
	 * la ACCV (({@link #URL_ACCV_WEBSERVICES URL_ACCV_WEBSERVICES})). Para obtener el 
	 * token se requiere una firma PKCS#7 y el documento que la originó.
	 * 
	 * @param document Documento que originó la firma PKCS#7
	 * @param pkcs7Signature Firma PKCS#7
	 * @throws HashingException No se puede obtener el hash del documento
	 * @throws MalformedTokenException El token obtenido no parece ser correcto
	 * @throws SignatureException El servicio web de la ACCV indica que la firma es
	 * 	incorrecta
	 * @throws ACCVWebServicesConnectionException No es posible conectarse y obtener
	 * 	una respuesta de la URL indicada
	 */
	public ACCVValidationToken (IDocument document, es.accv.arangi.base.signature.PKCS7Signature pkcs7Signature) throws HashingException, SignatureException, MalformedTokenException, ACCVWebServicesConnectionException {
		try {
			initialize(document, pkcs7Signature, new URL(ACCVValidationToken.URL_ACCV_WEBSERVICES));
		} catch (MalformedURLException e) {
			// No se va a dar
		}
	}
	
	/**
	 * Obtiene un token de validación conectándose a los servicios web de la ACCV (a la
	 * URL que se pasa como parámetro). Para obtener el token se requiere una firma PKCS#7
	 * y el documento que la originó.
	 * 
	 * @param document Documento que originó la firma PKCS#7
	 * @param pkcs7Signature Firma PKCS#7
	 * @param urlWebServices URL de los servicios web de la ACCV. Si la firma se
	 * 	realizó con un certificado de test habrá que utilizar los servicios web de
	 * 	test: {@link #URL_ACCV_WEBSERVICES_TEST URL_ACCV_WEBSERVICES_TEST}
	 * @throws HashingException No se puede obtener el hash del documento
	 * @throws MalformedTokenException El token obtenido no parece ser correcto
	 * @throws SignatureException El servicio web de la ACCV indica que la firma es
	 * 	incorrecta
	 * @throws ACCVWebServicesConnectionException No es posible conectarse y obtener
	 * 	una respuesta de la URL indicada
	 */
	public ACCVValidationToken (IDocument document, es.accv.arangi.base.signature.PKCS7Signature pkcs7Signature, URL urlWebServices) throws HashingException, SignatureException, MalformedTokenException, ACCVWebServicesConnectionException {
		initialize(document, pkcs7Signature, urlWebServices);
	}


	/* (non-Javadoc)
	 * @see es.accv.arangi.base.signature.ISignature#getCertificates()
	 */
	public Certificate[] getCertificates() {
		return pkcs7Signature.getCertificates();
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.base.signature.ISignature#getDocument()
	 */
	public IDocument getDocument() {
		return null;
	}

	/**
	 * El token de validación de la ACCV nunca contiene el documento firmado, por 
	 * lo que este método siempre lanzará una excepción {@link es.accv.arangi.base.exception.signature.NoDocumentToSignException NoDocumentToSignException}.
	 */
	public ValidationResult[] isValid(CAList arg0) throws HashingException, SignatureException, NormalizeCertificateException,
			NoDocumentToSignException {
		throw new NoDocumentToSignException ("El token de validación de la ACCV nunca contiene el documento firmado, " +
			"por lo que es imposible realizar esta validación");
	}

	/**
	 * Valida el token con la información que contiene.<br><br>
	 * 
	 * No utiliza para nada los servicios de validación pasados como parámetro, 
	 * pero el método debía estar presente para implementar la interfaz 
	 * {@link es.accv.arangi.base.signature.ISignature ISignature}.
	 * 
	 * @param document Documento que originó la firma
	 * @param caList Lista de certificados de CA
	 * @return Resultado de la validación (siempre contendrá un único elemento)
	 */
	public ValidationResult[] isValid(IDocument document, CAList caList) throws HashingException, SignatureException, NormalizeCertificateException {
		return isValid(document);
	}

	/**
	 * El token de validación de la ACCV nunca contiene el documento firmado, por 
	 * lo que este método siempre lanzará una excepción {@link es.accv.arangi.base.exception.signature.NoDocumentToSignException NoDocumentToSignException}.
	 */
	public ValidationResult[] isValid(List<CertificateValidationService> validationServices)
			throws HashingException, SignatureException, NormalizeCertificateException, NoDocumentToSignException {
		throw new NoDocumentToSignException ("El token de validación de la ACCV nunca contiene el documento firmado, " +
				"por lo que es imposible realizar esta validación");
	}

	/**
	 * Valida el token con la información que contiene.<br><br>
	 * 
	 * No utiliza para nada los servicios de validación pasados como parámetro, 
	 * pero el método debía estar presente para implementar la interfaz 
	 * {@link es.accv.arangi.base.signature.ISignature ISignature}.
	 * 
	 * @param document Documento que originó la firma
	 * @param validationServices Lista de servicios de validación de certificados
	 * @return Resultado de la validación (siempre contendrá un único elemento)
	 */
	public ValidationResult[] isValid(IDocument document, List<CertificateValidationService> validationServices)
			throws HashingException, SignatureException, NormalizeCertificateException {
		return isValid(document);
	}

	/**
	 * Valida el token realizando las siguientes comprobaciones:
	 * <ul>
	 * 	<li>Valida la firma del token.</li>
	 * 	<li>Valida que la firma PKCS#7 se corresponda con el documento.</li>
	 *  <li>Valida el sello de tiempos.</li>
	 *  <li>Comprueba que el sello de tiempos se realizase sobre la firma PKCS#7.</li>
	 *  <li>Comprueba que la fecha del sello de tiempos se encuentre dentro del
	 *  	periodo de validez de la respuesta OCSP.</li>
	 *  <li>Comprueba que la respuesta OCSP se corresponde con el certificado
	 *  	de la firma PKCS#7.</li>
	 *  <li>Comprueba que la respuesta OCSP es una respuesta de validez del
	 *  	certificado.</li>
	 * </ul>
	 * 
	 * @param document Documento que originó la firma
	 * @return Resultado de la validación (siempre contendrá un único elemento)
	 * @throws HashingException Error al hacer el hash del documento o del PKCS#7 
	 * 	contenido en el token
	 * @throws SignatureException Error comprobando la firma PKCS#7
	 */
	public ValidationResult[] isValid (IDocument document) throws HashingException, SignatureException, NormalizeCertificateException {
		return isValidWithHash(document.getHash());
	}
	
	/**
	 * Valida el token realizando las siguientes comprobaciones:
	 * <ul>
	 * 	<li>Valida la firma del token.</li>
	 * 	<li>Valida que la firma PKCS#7 se corresponda con el hash del documento.</li>
	 *  <li>Comprueba que la fecha del sello de tiempos se encuentre dentro del
	 *  	periodo de validez de la respuesta OCSP.</li>
	 *  <li>Comprueba que la respuesta OCSP se corresponde con el certificado
	 *  	de la firma PKCS#7.</li>
	 *  <li>Comprueba que la respuesta OCSP es una respuesta de validez del
	 *  	certificado.</li>
	 * </ul>
	 * 
	 * @param hash Hash del documento que originó la firma
	 * @return Resultado de la validación (siempre contendrá un único elemento)
	 * @throws HashingException Error al hacer el hash del PKCS#7 contenido en el token
	 * @throws SignatureException Error comprobando la firma PKCS#7
	 */
	public ValidationResult[] isValidWithHash (byte[] hash) throws SignatureException {
		logger.debug("[ACCVValidationToken.isValidWithHash]::Entrada::" + Arrays.asList(new Object[] { hash }));
		
		//-- Obtener el certificado del PKCS#7 (hará falta para devolver el resultado)
		Certificate certificate = null;
		if (getCertificates() != null && getCertificates().length > 0) {
			certificate = getCertificates()[0];
		}
				
		//-- Validar la firma del S-MIME
		try {
			SMIMESigned smimeSigned = new SMIMESigned((MimeMultipart) token.getContent());
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        smimeSigned.getContent().writeTo(baos);
	        ByteArrayDocument tokenDocument = new ByteArrayDocument(baos.toByteArray());
			ValidationResult[] validationResults = this.tokenSignature.isValidSignatureOnly(tokenDocument);
			for (int i = 0; i < validationResults.length; i++) {
				if (!validationResults[i].isValid()) {
					logger.debug("[ACCVValidationToken.isValidWithHash]::La firma del token no se corresponde con el contenido del mismo: " + validationResults[i].getResultText());
					return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_INVALID, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
				}
			}
		} catch (Exception e1) {
			logger.debug("[ACCVValidationToken.isValidWithHash]::No es posible validar la firma del token");
			return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_INVALID, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
		}
		
		//-- Verificar que la firma se corresponde con el documento
		ValidationResult[] validationResults = this.pkcs7Signature.isValidSignatureOnlyWithHash(hash);
		for (int i = 0; i < validationResults.length; i++) {
			if (!validationResults[i].isValid()) {
				logger.debug("[ACCVValidationToken.isValidWithHash]::El PKCS#7 no se corresponde con el documento: " + validationResults[i].getResultText());
				return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_SIGNATURE_NOT_MATCH_DATA, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
			}
		}
		
		//-- Validar el sello de tiempos
		boolean timeStampValid;
		try {
			timeStampValid = this.timeStamp.isValid();
		} catch (MalformedTimeStampException e) {
			logger.debug("[ACCVValidationToken.isValidWithHash]::El sello de tiempos se halla mal formado", e);
			return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_INVALID_TIMESTAMP, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
		}
		if (!timeStampValid) {
			//-- Los tokens antiguos siempre tienen mal el sello, no se validará
			logger.debug("[ACCVValidationToken.isValidWithHash]::El sello de tiempos no es válido");
		}
		
		//-- Fecha del sello de tiempos
		Date tsDate = this.timeStamp.getTime();
		
		//-- Comprobar que la fecha del sello de tiempos está dentro del periodo de
		//-- Validez de la respuesta OCSP
		CertificateOCSPResponse[] ocspResponses = this.ocspResponse.getSingleResponses();
		for(int i=0;i<ocspResponses.length;i++) {
			if (ocspResponses[i].getValidityPeriodBeginning().after(tsDate) ||
					ocspResponses[i].getValidityPeriodEnd().before(tsDate)) {
				logger.debug("[ACCVValidationToken.isValidWithHash]::La fecha del sello de tiempos no se encuentra en el periodo de validez de la respuesta OCSP");
				return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_TIMESTAMP_AFTER_VALIDITY_ITEM, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
			}
		}
		
		//-- Comprobar que la respuesta OCSP se corresponde con el certificado del PKCS#7
		for(int i=0;i<ocspResponses.length;i++) {
			if (!ocspResponses[i].match(certificate)) {
				logger.debug("[ACCVValidationToken.isValidWithHash]::La respuesta OCSP del token no se corresponde con el certificado");
				return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_INVALID_VALIDITY_ITEM, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
			}
		}
		
		//-- Comprobar que la respuesta OCSP es de validez
		for(int i=0;i<ocspResponses.length;i++) {
			if (ocspResponses[i].getStatus() != ValidationResult.RESULT_VALID) {
				logger.debug("[ACCVValidationToken.isValidWithHash]::La respuesta OCSP del token no es una respuesta válida: " + ocspResponses[i].getStatus());
				return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_INVALID_VALIDITY_ITEM, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
			}
		}
		
		//-- Todo OK
		logger.debug("[ACCVValidationToken.isValidWithHash]::TOKEN VÁLIDO");
		return new ValidationResult[] {new ValidationResult(ValidationResult.RESULT_VALID, certificate.toX509Certificate(), null, getTimeStamp(), new OCSPResponse[] { getOcspResponse() }) };
	}
	
	/**
	 * Valida el token realizando las siguientes comprobaciones:
	 * <ul>
	 * 	<li>Valida la firma del token.</li>
	 * 	<li>Valida que la firma PKCS#7 se corresponda con el hash del documento.</li>
	 *  <li>Comprueba que la fecha del sello de tiempos se encuentre dentro del
	 *  	periodo de validez de la respuesta OCSP.</li>
	 *  <li>Comprueba que la respuesta OCSP se corresponde con el certificado
	 *  	de la firma PKCS#7.</li>
	 *  <li>Comprueba que la respuesta OCSP es una respuesta de validez del
	 *  	certificado.</li>
	 * </ul><br><br>
	 * 
	 * Obtiene un XML que contendrá el resultado:
	 * <ul>
	 * 	<li>APLICACION: si aparece este tag es que la firma se ha podido validar</li>
	 *  <li>ERROR: se ha producido un error durante la validación o alguno de los
	 *  	elementos del token no es válido</li>
	 *  <li>FIRMA: si indica "Fallo al verificar la firma" es porque el documento
	 *  	no se corresponde con la firma. En caso contrario es que el token es
	 *  	valido y se muestra: FIRMANTE y CERTIFICADO</li>
	 * </ul><br><br>
	 * 
	 * El resultad de este método es el mismo de llamar al método <code>getVerifyToken_hash</code>
	 * de los servicios web de validación de la ACCV.
	 * 
	 * @param hash Hash del documento que originó la firma
	 * @throws HashingException Error al hacer el hash del PKCS#7 contenido en el token
	 * @throws SignatureException Error comprobando la firma PKCS#7
	 */
	public String getValidationXML (byte[] hash) {
		logger.debug("[ACCVValidationToken.getValidationXML]::Entrada::" + Arrays.asList(new Object[] { hash }));
		
		//-- Obtener el certificado del PKCS#7 (hará falta para devolver el resultado)
		Certificate certificate = null;
		if (getCertificates() != null && getCertificates().length > 0) {
			certificate = getCertificates()[0];
		}
				
		//-- Validar la firma del S-MIME
		try {
			SMIMESigned smimeSigned = new SMIMESigned((MimeMultipart) token.getContent());
	        ByteArrayOutputStream baos = new ByteArrayOutputStream();
	        smimeSigned.getContent().writeTo(baos);
	        ByteArrayDocument tokenDocument = new ByteArrayDocument(baos.toByteArray());
			ValidationResult[] validationResults = this.tokenSignature.isValidSignatureOnly(tokenDocument);
			for (int i = 0; i < validationResults.length; i++) {
				if (!validationResults[i].isValid()) {
					logger.debug("[ACCVValidationToken.getValidationXML]::La firma del token no se corresponde con el contenido del mismo: " + validationResults[i].getResultText());
					return getXMLValidacionError();
				}
			}
		} catch (Exception e) {
			logger.debug("[ACCVValidationToken.getValidationXML]::No es posible validar la firma del token", e);
			return getXMLValidacionError();
		}
		
		//-- Verificar que la firma se corresponde con el documento
		ValidationResult[] validationResults;
		try {
			validationResults = this.pkcs7Signature.isValidSignatureOnlyWithHash(hash);
		} catch (SignatureException e1) {
			logger.debug("[ACCVValidationToken.getValidationXML]::Error validando el PKCS#7");
			return getXMLFirmaDocumentoNoMatch();
		}
		for (int i = 0; i < validationResults.length; i++) {
			if (!validationResults[i].isValid()) {
				logger.debug("[ACCVValidationToken.getValidationXML]::El PKCS#7 no se corresponde con el documento: " + validationResults[i].getResultText());
				return getXMLFirmaDocumentoNoMatch();
			}
		}
		
		//-- Validar el sello de tiempos
		String textoTS = null;
		try {
			if (!this.timeStamp.isValid()) {
				//-- Los tokens antiguos siempre tienen mal el sello, no se validará
				logger.debug("[ACCVValidationToken.getValidationXML]::El sello de tiempos no es válido");
			}
		} catch (MalformedTimeStampException e) {
			logger.debug("[ACCVValidationToken.getValidationXML]::El sello de tiempos se halla mal formado", e);
			textoTS = "Fallo al verificar el sello de tiempos";
		}
		
		//-- Fecha del sello de tiempos
		Date tsDate = this.timeStamp.getTime();
		
		//-- Comprobar que la fecha del sello de tiempos está dentro del periodo de
		//-- Validez de la respuesta OCSP
		String textoOCSP = null;
		CertificateOCSPResponse[] ocspResponses = this.ocspResponse.getSingleResponses();
		for(int i=0;i<ocspResponses.length;i++) {
			if (ocspResponses[i].getValidityPeriodBeginning().after(tsDate) ||
					ocspResponses[i].getValidityPeriodEnd().before(tsDate)) {
				logger.debug("[ACCVValidationToken.getValidationXML]::La fecha del sello de tiempos no se encuentra en el periodo de validez de la respuesta OCSP");
				textoOCSP = "No es valida en la fecha del sello";
			}
		}
		
		//-- Comprobar que la respuesta OCSP se corresponde con el certificado del PKCS#7
		for(int i=0;i<ocspResponses.length;i++) {
			if (!ocspResponses[i].match(certificate)) {
				logger.debug("[ACCVValidationToken.getValidationXML]::La respuesta OCSP del token no se corresponde con el certificado");
				textoOCSP = "No valida";
			}
		}
		
		//-- Comprobar que la respuesta OCSP es de validez
		for(int i=0;i<ocspResponses.length;i++) {
			if (ocspResponses[i].getStatus() != ValidationResult.RESULT_VALID) {
				logger.debug("[ACCVValidationToken.getValidationXML]::La respuesta OCSP del token no es una respuesta válida: " + ocspResponses[i].getStatus());
				textoOCSP = "No valida";
			}
		}
		
		//-- Resultado
		logger.debug("[ACCVValidationToken.getValidationXML]::TOKEN VÁLIDO");
		return getXMLFirmaOk (textoTS, textoOCSP, certificate, tsDate);
	}
	
	/**
	 * Método que se conecta a la URL de los servicios web de la ACCV (pasada como
	 * parámetro) para validar el token de validación.
	 * 
	 * @param document Documento que originó la firma del token
	 * @param urlWebServices URL de los servicios web de la ACCV. Si la firma se
	 * 	realizó con un certificado de test habrá que utilizar los servicios web de
	 * 	test: {@link #URL_ACCV_WEBSERVICES_TEST URL_ACCV_WEBSERVICES_TEST}
	 * @return Cierto si el token es válido
	 * @throws HashingException No se puede obtener el hash del documento
	 * @throws ACCVWebServicesConnectionException No es posible conectarse y obtener
	 * 	una respuesta de la URL indicada
	 */
	public boolean isValid (IDocument document, URL urlWebServices) throws HashingException, ACCVWebServicesConnectionException {
		logger.debug("[ACCVValidationToken.isValid]::Entrada::" + document);
		
		//-- Construir el mensaje SOAP
		String message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
			"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
			"<soapenv:Body><ns1:getEstadoToken_hash soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"urn:serviciospki\">" +
			"<in0 xsi:type=\"xsd:string\">" + new String (Hex.encode(document.getHash())) + "</in0>" +
			"<in1 xsi:type=\"xsd:string\">" + new String (this.tokenB64) + "</in1>" +
			"</ns1:getEstadoToken_hash></soapenv:Body></soapenv:Envelope>";
		
		try {
			
			StringBuffer sb = Util.sendPost(message, urlWebServices);
			
			//-- Evaluar la respuesta
			if (sb.indexOf("-1") > -1) {
				return false;
			} else {
				return true;
			}
			
		} catch (ServiceNotFoundException e) {
			logger.info("[ACCVValidationToken.isValid]::Error de conexión en la URL '" + urlWebServices + "'", e);
			throw new ACCVWebServicesConnectionException ("Error de conexión en la URL '" + urlWebServices + "'", e);
		} catch (ServiceException e) {
			logger.info("[ACCVValidationToken.isValid]::No se puede obtener una respuesta correcta de la URL '" + urlWebServices + "'", e);
			throw new ACCVWebServicesConnectionException ("No se puede obtener una respuesta correcta de la URL '" + urlWebServices + "'", e);
		}

	}
	
	/**
	 * El token de validación de la ACCV nunca contiene el documento firmado, por 
	 * lo que este método siempre lanzará una excepción {@link es.accv.arangi.base.exception.signature.NoDocumentToSignException NoDocumentToSignException}.
	 */
	public ValidationResult[] isValidSignatureOnly() throws HashingException, SignatureException, NoDocumentToSignException {
		throw new NoDocumentToSignException ("El token de validación de la ACCV nunca contiene el documento firmado, " +
				"por lo que es imposible realizar esta validación");
	}

	/**
	 * Sólo comprueba que la firma PKCS#7 contenida es correcta
	 */
	public ValidationResult[] isValidSignatureOnly(IDocument document) throws HashingException, SignatureException {
		return pkcs7Signature.isValidSignatureOnly(document);
	}

//	
// Haría falta hacer el resellado en servidor ya que al final hay que volver a firmar el SMIME para que siga siendo válido
//	
//	public void addArchiveTimeStamp () throws OCSPException, OCSPValidateException, MalformedTokenException, 
//		CertificateCANotFoundException, NormalizeCertificateException, MalformedTimeStampException, 
//		ResponseTimeStampException, HashingException, TimeStampServerConnectionException {
//		
//		logger.debug("[ACCVValidationToken.addArchiveTimeStamp]::Entrada");
//		
//		//-- Obtener las partes del smime
//		Multipart multipart;
//		try {
//			SMIMESigned smimeSigned = new SMIMESigned((MimeMultipart) token.getContent());
//			multipart = (Multipart) smimeSigned.getContent().getContent();
//		} catch (Exception e) {
//			logger.info("[ACCVValidationToken.addArchiveTimeStamp]::No se ha podido leer el SMIME", e);
//			throw new MalformedTokenException ("No se ha podido leer el SMIME", e);
//		} 	
//		
//		//-- Obtener el certificado del sello de tiempos
//		ValidateCertificate tsCertificate = new ValidateCertificate (timeStamp.getSignatureCertificate().toX509Certificate(), 
//				ArangiUtil.getACCVCaList());
//		if (tsCertificate.validate() != ValidationResult.RESULT_VALID) {
//			logger.error ("El certificado del sello ya no es válido: \n" + tsCertificate);
//			throw new OCSPValidateException("El certificado del sello ya no es válido: \n" + tsCertificate);
//		}
//		
//		//-- Obtener la respuesta ocsp para el certificado
//		logger.debug("[ACCVValidationToken.addArchiveTimeStamp]::Obtener la respuesta ocsp para el certificado");
//		OCSPResponse ocspResponse = null;
//		for (OCSPClient ocspClient : tsCertificate.getOCSPClients()) {
//			try {
//				ocspResponse = ocspClient.getOCSPResponse(tsCertificate);
//				break;
//			} catch (Exception e) {
//				logger.debug("No se puede validar contra el OCSP: " + ocspClient.getURL(), e);
//			} 
//		}
//		
//		if (ocspResponse == null || ocspResponse.getSingleResponses().length == 0) {
//			//-- No se ha podido obtener la respuesta
//			logger.error ("No es posible obtener la respuesta OCSP para el certificado: \n" + tsCertificate);
//			throw new OCSPException("No es posible obtener la respuesta OCSP para el certificado");
//		}
//		if (ocspResponse.getSingleResponses()[0].getStatus() != ValidationResult.RESULT_VALID) {
//			//-- El certificado del sello ya no es válido
//			logger.error ("El certificado del sello ya no es válido: \n" + tsCertificate);
//			throw new OCSPValidateException("El certificado del sello ya no es válido: \n" + tsCertificate);
//		}
//
//		try {
//			//-- Crear el mimepart
//			logger.debug("[ACCVValidationToken.addArchiveTimeStamp]::Crear el mimepart para la respuesta ocsp del certificado del sello");
//			BodyPart mimeBodyPart = new MimeBodyPart();
//		    mimeBodyPart.setFileName("OCSPTS");
//		    mimeBodyPart.setDataHandler(new DataHandler(new TokenDataSource(ocspResponse.toDER(), "application/octet-stream", "OCSPTS")));
//		    mimeBodyPart.addHeader("Content-Transfer-Encoding", "base64");
//		    multipart.addBodyPart(mimeBodyPart);
//		} catch (Exception e) {
//			logger.info("[ACCVValidationToken.addArchiveTimeStamp]::No se han podido añadir las nuevas partes del SMIME", e);
//			throw new MalformedTokenException ("No se han podido añadir las nuevas partes del SMIME", e);
//		} 	
//		    
//	    //-- Recoger todo y sellar
//		logger.debug("[ACCVValidationToken.addArchiveTimeStamp]::Obtener el sello de tiempos de archivo");
//	    InputStream is;
//		try {
//			is = token.getInputStream();
//		} catch (Exception e) {
//			logger.info("[ACCVValidationToken.addArchiveTimeStamp]::No se han podido obtener el stream de lectura del SMIME", e);
//			throw new MalformedTokenException ("No se han podido obtener el stream de lectura del SMIME", e);
//		} 
//	    TimeStamp archiveTs = TimeStamp.stampDocument(is);
//			
//		try {
//		    logger.debug("[ACCVValidationToken.addArchiveTimeStamp]::Crear el mimepart con el sello de tiempos de archivo");
//		    BodyPart mimeBodyPart = new MimeBodyPart();
//		    mimeBodyPart.setFileName("TSSARCHIVO");
//		    mimeBodyPart.setDataHandler(new DataHandler(new TokenDataSource(archiveTs.toDER(), "application/octet-stream", "TSSARCHIVO")));
//		    mimeBodyPart.addHeader("Content-Transfer-Encoding", "base64");
//		    multipart.addBodyPart(mimeBodyPart);
//		} catch (Exception e) {
//			logger.info("[ACCVValidationToken.addArchiveTimeStamp]::No se han podido añadir las nuevas partes del SMIME", e);
//			throw new MalformedTokenException ("No se han podido añadir las nuevas partes del SMIME", e);
//		} 	
//	    
//	    //-- Cargar objetos
//	    this.archiveTimeStamp = archiveTs;
//	    this.tsCertificateOcspResponse = ocspResponse;
//	    try {
//			this.tokenB64 = Util.encodeBase64(this.token.getInputStream()).getBytes();
//		} catch (Exception e) {
//			logger.info("[ACCVValidationToken.addArchiveTimeStamp]::No se han podido obtener el stream de lectura del SMIME", e);
//			throw new MalformedTokenException ("No se han podido obtener el stream de lectura del SMIME", e);
//		} 
//	}
	
	/**
	 * Obtiene el sello de tiempos del token de validación
	 * 
	 * @return Sello de tiempos del token de validación
	 */
	public TimeStamp getTimeStamp() {
		return timeStamp;
	}

	/**
	 * Obtiene la respuesta OCSP del token de validación
	 * 
	 * @return Respuesta OCSP del token de validación
	 */
	public OCSPResponse getOcspResponse() {
		return ocspResponse;
	}

	/**
	 * Obtiene la firma PKCS#7 contenida en el token de validación
	 * 
	 * @return Firma PKCS#7 contenida en el token de validación
	 */
	public PKCS7Signature getPkcs7Signature() {
		return pkcs7Signature;
	}

	/**
	 * Guarda la firma en disco
	 * 
	 * @param file Fichero donde se guardará la firma
	 * @throws IOException Errores de entrada / salida
	 */
	public void save (File file) throws IOException {
		logger.debug ("[CMSPKCS7Signature.save]::Entrada::" + file);
		
		Util.saveFile(file, this.tokenB64);
	}
	
	/**
	 * Guarda la firma en un stream de escritura.
	 * 
	 * @param out Stream de escritura
	 * @throws IOException Errores de entrada / salida
	 */
	public void save (OutputStream out) throws IOException {
		logger.debug ("[CMSPKCS7Signature.save]::Entrada::" + out);
		
		Util.save(out, this.tokenB64);
	}
	
	/**
	 * Obtiene una respuesta de error para el método getValidationXML
	 */
	public static String getXMLValidacionError() {
		return "<?xml version=\"1.0\"?><ERROR><FIRMA>No se ha podido verificar la firma de la aplicacion.</FIRMA></ERROR>";
	}

	/**
	 * Método para poder validar con el método Signature.validateSignature.<br><br>
	 * 
	 * Analiza el parámetro y, si se trata de un token de validación
	 * ACCV, devuelve un objeto de este tipo.
	 * 
	 * @param bSignature Firma como array de bytes
	 * @return Token de validación ACCV
	 * @throws Exception El parámetro no es un token de validación ACCV
	 */
	public static ISignature getSignatureInstance (byte[] bSignature) throws Exception {
		return new ACCVValidationToken(bSignature);
	}
	
	/**
	 * Añade esta clase a la lista de clases reconocedoras de firmas. A partir
	 * de este momento, si se usan las instrucciones Signature.validateSignature
	 * se tendrá en cuenta que la firma puede ser un token de validación de la ACCV.
	 */
	public static void addClassToSignatureValidation () {
		Signature.addRecognizerClass(ACCVValidationToken.class);
	}

	/**
	 * Obtiene el token de validación de la ACCV en base64
	 * 
	 * @return Token de validación
	 */
	public byte[] toByteArray() {
		return this.tokenB64;
	}

	public String getSignatureType() {
		return "Token Validación ACCV";
	}

	//-- Métodos privados
	
	/*
	 * Inicializa este objeto
	 */
	private void initialize(byte[] bytesToken) throws MalformedTokenException {
		
		logger.debug("[ACCVValidationToken.initialize]::Entrada::" + bytesToken);
		
		//-- Pasar de base64
		ByteArrayInputStream bais = new ByteArrayInputStream (Util.decodeBase64(new String (bytesToken)));
		
		try {
			
			//-- Nos creamos el objeto sesión.
			Properties properties = new Properties();
			Session session = Session.getDefaultInstance(properties, null);
		    
			//-- Obtenemos el mensaje	
			token = new MimeMessage(session, bais);
			SMIMESigned smimeSigned = new SMIMESigned((MimeMultipart) token.getContent());
			Multipart multiPart = (Multipart) smimeSigned.getContent().getContent();
			if (multiPart.getCount() != 3) {
				throw new SignatureException("El token contiene " + multiPart.getCount() + " multiparts en lugar de 3");
			}
			
			//-- Procesamos la firma del usuario
			MimeBodyPart partFirma = (MimeBodyPart) multiPart.getBodyPart(0);
			SharedByteArrayInputStream sbais = (SharedByteArrayInputStream)partFirma.getContent();
			String pkcs7SignatureB64 = new String(Util.readStream(sbais));			
			pkcs7Signature = new PKCS7Signature (Util.decodeBase64(pkcs7SignatureB64));
	
			//-- Procesamos el OCSP
			MimeBodyPart partOCSP = (MimeBodyPart) multiPart.getBodyPart(1);
			com.sun.mail.util.BASE64DecoderStream decoderStream = (com.sun.mail.util.BASE64DecoderStream)partOCSP.getContent();
		    byte[] abRet = new byte[decoderStream.available()];
		    decoderStream.read(abRet);
			ocspResponse = new OCSPResponse(abRet);
      
			//-- Procesamos el Token TSS	
			MimeBodyPart partTSS = (MimeBodyPart) multiPart.getBodyPart(2);
			decoderStream = (com.sun.mail.util.BASE64DecoderStream)partTSS.getContent();
		    abRet = new byte[decoderStream.available()];
		    decoderStream.read(abRet);
			timeStamp = new TimeStamp (abRet);		
			
			//-- Procesamos la firma del token
			tokenSignature = new PKCS7Signature (smimeSigned.getEncoded());
			
			//-- Guardar el mensaje en su campo
			tokenB64 = bytesToken;
			
		} catch (MessagingException e) {
			logger.info("[ACCVValidationToken.initialize]::El token no es un SMIME correcto", e);
			throw new MalformedTokenException ("El token no es un SMIME correcto", e);
		} catch (IOException e) {
			logger.info("[ACCVValidationToken.initialize]::No se puede leer alguna de las partes del token", e);
			throw new MalformedTokenException ("No se puede leer alguna de las partes del token", e);
		} catch (CMSException e) {
			logger.info("[ACCVValidationToken.initialize]::No se ha encontrado la firma del SMIME o ésta no es correcta", e);
			throw new MalformedTokenException ("No se ha encontrado la firma del SMIME o ésta no es correcta", e);
		} catch (NormalizeCertificateException e) {
			logger.info("[ACCVValidationToken.initialize]::El certificado de la firma PKCS#7 no puede ser tratado por el proveedor criptográfico de Arangi", e);
			throw new MalformedTokenException ("El certificado de la firma PKCS#7 no puede ser tratado por el proveedor criptográfico de Arangi", e);
		} catch (MalformedOCSPResponseException e) {
			logger.info("[ACCVValidationToken.initialize]::La respuesta OCSP del token no está bien construída", e);
			throw new MalformedTokenException ("La respuesta OCSP del token no está bien construída", e);
		} catch (MalformedTimeStampException e) {
			logger.info("[ACCVValidationToken.initialize]::El sello de tiempos del token no está bien construído", e);
			throw new MalformedTokenException ("El sello de tiempos del token no está bien construído", e);
		} catch (SignatureException e) {
			logger.info("[ACCVValidationToken.initialize]::Error obteniendo los certificados del PKCS#7", e);
			throw new MalformedTokenException ("Error obteniendo los certificados del PKCS#7", e);
		} catch (Exception e) {
			logger.info("[ACCVValidationToken.initialize]::La firma no parece un token de validación de la ACCV en base64", e);
			throw new MalformedTokenException ("La firma no parece un token de validación de la ACCV en base64", e);
		}
		
	}
	
	/*
	 * Obtiene un token de validación conectándose a los servicios web de la ACCV (a la
	 * URL que se pasa como parámetro). Para obtener el token se requiere una firma PKCS#7
	 * y el documento que la originó.
	 * 
	 * @param document Documento que originó la firma PKCS#7
	 * @param pkcs7Signature Firma PKCS#7
	 * @param urlWebServices URL de los servicios web de la ACCV. Si la firma se
	 * 	realizó con un certificado de test habrá que utilizar los servicios web de
	 * 	test: {@link URL_ACCV_WEBSERVICES_TEST URL_ACCV_WEBSERVICES_TEST}
	 * @throws HashingException No se puede obtener el hash del documento
	 * @throws MalformedTokenException El token obtenido no parece ser correcto
	 * @throws SignatureException El servicio web de la ACCV indica que la firma es
	 * 	incorrecta
	 * @throws ACCVWebServicesConnectionException No es posible conectarse y obtener
	 * 	una respuesta de la URL indicada
	 */
	private void initialize (IDocument document, es.accv.arangi.base.signature.PKCS7Signature pkcs7Signature, URL urlWebServices) throws HashingException, SignatureException, MalformedTokenException, ACCVWebServicesConnectionException {
		logger.debug("[ACCVValidationToken.initialize]::Entrada::" + document);
		
		//-- Construir el mensaje SOAP
		String message = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
			"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
			"<soapenv:Body><ns1:getToken_hash soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:ns1=\"urn:serviciospki\">" +
			"<in0 xsi:type=\"xsd:string\">" + new String (Hex.encode(document.getHash())) + "</in0>" +
			"<in1 xsi:type=\"xsd:string\">" + Util.encodeBase64(pkcs7Signature.toByteArray()) + "</in1>" +
			"</ns1:getToken_hash></soapenv:Body></soapenv:Envelope>";
		
		StringBuffer sb;
		try {
			sb = Util.sendPost(message, urlWebServices);
			logger.debug("[ACCVValidationToken.initialize]::Response::" + sb.toString());
			
		} catch (ServiceNotFoundException e) {
			logger.info("[ACCVValidationToken.isValid]::Error de conexión en la URL '" + urlWebServices + "'", e);
			throw new ACCVWebServicesConnectionException ("Error de conexión en la URL '" + urlWebServices + "'", e);
		} catch (ServiceException e) {
			logger.info("[ACCVValidationToken.isValid]::No se puede obtener una respuesta correcta de la URL '" + urlWebServices + "'", e);
			throw new ACCVWebServicesConnectionException ("No se puede obtener una respuesta correcta de la URL '" + urlWebServices + "'", e);
		}

		//-- Evaluar la respuesta
		if (sb.indexOf("getToken_hashReturn") > -1) {
			
			String finalMessage = sb.substring(sb.indexOf("getToken_hashReturn"));
			finalMessage = finalMessage.substring(finalMessage.indexOf(">") + 1);
			finalMessage = finalMessage.substring(0, finalMessage.indexOf("<"));
			if (finalMessage.equals("Fallo al verificar la firma.")) {
				logger.info("[ACCVValidationToken.initialize]::Fallo al verificar la firma");
				throw new SignatureException ("El servicio web de la ACCV devuelve un fallo al verificar la firma");
			}
			if (finalMessage.equals("Imposible comprobar el Certificado")) {
				logger.info("[ACCVValidationToken.initialize]::Imposible comprobar el Certificado");
				throw new SignatureException ("El servicio web de la ACCV devuelve que es imposible comprobar el certificado");
			}
			
			initialize(finalMessage.getBytes());
		}
	}

	/*
	 * Obtiene una respuesta de que el documento no hace match con la firma
	 * para el método getValidationXML
	 */
	private static String getXMLFirmaDocumentoNoMatch() {
		return "<?xml version=\"1.0\"?><APLICACION>Se ha verificado la firma de la aplicacion</APLICACION><FIRMA>Fallo al verificar la firma</FIRMA>";
	}

	/*
	 * Obtiene una respuesta válida o no válida
	 */
	private static String getXMLFirmaOk(String textoTS,
			String textoOCSP, Certificate certificate, Date tsDate) {
		return "<?xml version=\"1.0\"?><APLICACION>Se ha verificado la firma de la aplicacion</APLICACION>" +
				"<FIRMA>Resultado de la firma original<FIRMANTE>" + certificate.getSubjectDN().replaceAll("SERIALNUMBER=", "SN=") + "</FIRMANTE>" +
				"<CERTIFICADO>" + (textoOCSP != null ? "Certificado no Valido" : "Certificado Valido") + 
				"</CERTIFICADO></FIRMA><OCSP>" + (textoOCSP != null ? textoOCSP : "Valido") + 
				"</OCSP><TSS>" + (textoTS != null ? textoTS : VALIDATION_XML_DATE_FORMAT.format(tsDate)) + "</TSS>";
	}

	//-- Clases
	
	/**
	 * Clase para añadir a cada MimeBodyPart su contenido 
	 */
	public class TokenDataSource implements DataSource {
		
		byte[] contenido;
		String contentType;
		String name;
		
		public TokenDataSource (byte[] contenido, String contentType, String name) {
			this.contenido = contenido;
			this.contentType = contentType;
			this.name = name;
		}

		public String getContentType() {
			return this.contentType;
		}

		public InputStream getInputStream() throws IOException {
			return new ByteArrayInputStream(this.contenido);
		}

		public String getName() {
			return this.name;
		}

		public OutputStream getOutputStream() throws IOException {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			return baos;
		}
		
	}

}
