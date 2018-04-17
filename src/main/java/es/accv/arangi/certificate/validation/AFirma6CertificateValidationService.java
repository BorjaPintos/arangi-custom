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
package es.accv.arangi.certificate.validation;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.validation.CertificateValidationService;
import es.accv.arangi.base.certificate.validation.CertificateValidationServiceResult;
import es.accv.arangi.base.certificate.validation.OCSPResponse;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.validation.ServiceException;
import es.accv.arangi.base.exception.certificate.validation.ServiceNotFoundException;
import es.accv.arangi.base.util.Util;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerContent;
import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ReportDetailLevel;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.GeneralConstants;

/**
 * Clase que implementa la validaci�n de certificados mediante llamadas 
 * a los servicios web DSS de &#64;Firma6.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� Manuel Guti�rrez N��ez</a>
 *
 */
public class AFirma6CertificateValidationService implements CertificateValidationService {
	
	/*
	 * Minor result: el certificado no est� entre los tratados
	 */
	public static final String AFIRMA_MINOR_RESULT_CERTIFICATE_NOT_SUPPORTED = "urn:afirma:dss:1.0:profile:XSS:resultminor:Certificate:NotSupported";
	
	/*
	 * Minor result: el certificado est� revocado
	 */
	public static final String AFIRMA_MINOR_RESULT_CERTIFICATE_REVOKED = "urn:oasis:names:tc:dss:1.0:profiles:XSS:resultminor:invalid:certificate:Revoked";
	
	/*
	 * Constantes para la clasificaci�n de certificados de @Firma
	 */
	private static final int AFIRMA_CLASIFICACION_PERSONA_FISICA	= 0;
	private static final int AFIRMA_CLASIFICACION_PERSONA_JURIDICA	= 1;
	private static final int AFIRMA_CLASIFICACION_EMPLEADO_PUBLICO	= 5;
	private static final int AFIRMA_CLASIFICACION_ENTIDAD			= 6;
	private static final int AFIRMA_CLASIFICACION_CUALIFICADO_SELLO	= 8;
	private static final int AFIRMA_CLASIFICACION_AUTENTICACION		= 9;
	private static final int AFIRMA_CLASIFICACION_REPRESENTANTE_CPJ	= 11;
	private static final int AFIRMA_CLASIFICACION_REPRESENTANTE_SPJ	= 12;

	/*
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(AFirma6CertificateValidationService.class);
	
	/*
	 * URL de acceso a los servicios web de &#64;Firma
	 */
	private String url;
	
	/*
	 * Identificador de la aplicaci�n en &#64;Firma
	 */
	private String idAplicacion;
	
	/*
	 * Usuario 
	 */
	private String user;
	
	/*
	 * Contrase�a
	 */
	private String password;
	
	/*
	 * Fichero de acceso a almac�n de claves (WSS4J)
	 */
	private String configuracionWSS4J;
	
	//-- Constructores	
	
	/**
	 * Constructor por defecto: si se usa este constructor ser� necesario inicializar
	 * el objeto.
	 */
	public AFirma6CertificateValidationService() {
		super();
	}
	
	/**
	 * Constructor en el que pasar la informaci�n necesaria para crear 
	 * este objeto.
	 * 
	 * @param url URL al servico web de &#64;Firma. Los posibles valores se pueden
	 * 	encontrar en los campos est�ticos de esta clase PRODUCTION_URL y
	 *  TEST_URL.
	 * @param idAplicacion ID de su aplicaci�n. Este valor se le entreg� en
	 * 	el momento en que su aplicaci�n fue dada de alta en la plataforma
	 * @param user Nombre de usuario para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contrase�a.
	 * @param password Contrase�a para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contrase�a.
	 * @param configuracionWSS4J Fichero que contiene la informaci�n de acceso al
	 * 	certificado que firmar� las peticiones que se env�an a @Firma 
	 */
	public AFirma6CertificateValidationService(String url, String idAplicacion, String user,
			String password, String configuracionWSS4J) {
		super();
		initialize(url, idAplicacion, user, password, configuracionWSS4J);
	}

	/**
	 * Constructor en el que pasar la informaci�n necesaria para crear 
	 * este objeto.
	 * 
	 * @param parameters Parametros necesarios para la inicializaci�n
	 */
	public AFirma6CertificateValidationService(AFirma6CertificateValidationParameters parameters) {
		super();
		initialize(parameters.getAFirma6URL(), parameters.getAFirma6IdAplicacion(), parameters.getAFirma6User(), 
				parameters.getAFirma6Password(), parameters.getAFirma6ConfiguracionWSS4J());
	}
	/**
	 * Inicializa el objeto
	 * 
	 * @param url URL al servico web de &#64;Firma. Los posibles valores se pueden
	 * 	encontrar en los campos est�ticos de esta clase PRODUCTION_URL y
	 *  TEST_URL.
	 * @param idAplicacion ID de su aplicaci�n. Este valor se le entreg� en
	 * 	el momento en que su aplicaci�n fue dada de alta en la plataforma
	 * @param user Nombre de usuario para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contrase�a.
	 * @param password Contrase�a para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contrase�a.
	 * @param configuracionWSS4J Fichero que contiene la informaci�n de acceso al
	 * 	certificado que firmar� las peticiones que se env�an a @Firma 
	 */
	public void initialize (String url, String idAplicacion, String user, String password, String configuracionWSS4J) {
		this.idAplicacion = idAplicacion;
		this.user = user;
		this.password = password;
		this.configuracionWSS4J = configuracionWSS4J;
		
		if (url.indexOf("//") > -1) {
			url = url.substring(url.indexOf("//") + 2);
			if (url.indexOf("/") > -1) {
				url = url.substring(0, url.indexOf("/"));
			}
		}
		this.url = url;
	}

	/**
	 * Valida un certificado mediante una llamada a un servicio externo.
	 * 
	 * @param certificate Certificado a validar
	 * @param extraParams Par�metros extra por si fueran necesarios para 
	 * 	realizar la validaci�n
	 * @return Objeto con el resultado y, si el servicio web lo permite, los
	 * 	campos m�s significativos del certificado.
	 * @throws ServiceNotFoundException El servicio no se encuentra disponible
	 * @throws ServiceException La llamada al servicio devuelve un error
	 */
	public CertificateValidationServiceResult validate(Certificate certificate, 
			Map<String, Object> extraParams) throws ServiceNotFoundException, ServiceException {
		
		logger.debug("[AFirmaCertificateValidationService.validate]::Entrada::" + Arrays.asList(new Object[] { certificate, extraParams }));
		
		//-- Pasar los par�metros a un properties
		ArangiServiceContent serviceContent = new ArangiServiceContent(url, user, password, configuracionWSS4J);
		
		Map<String, Object> inParams = new HashMap<String, Object>();

		inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, this.idAplicacion);
		inParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
		inParams.put(DSSTagsRequest.INCLUDE_REVOCATION, "true");
		inParams.put(DSSTagsRequest.REPORT_DETAIL_LEVEL, ReportDetailLevel.ALL_DETAILS);
		inParams.put(DSSTagsRequest.CHECK_CERTIFICATE_STATUS, "true");
		inParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
		try {
			inParams.put(DSSTagsRequest.X509_CERTIFICATE, Util.encodeBase64(certificate.toDER()));
		} catch (NormalizeCertificateException e) {
			//-- El certificado ya se normaliz� al entrar, no se dar� el error
			logger.info ("[AFirmaCertificateValidationService.validate]", e);
		}
		
		String xmlInput;
		try {
			xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
		} catch (TransformersException e) {
			logger.info("No se puede crear la petici�n para @Firma", e);
			throw new ServiceException("No se puede crear la petici�n para @Firma", e);
		}
		String xmlOutput;
		try {
			xmlOutput = Afirma5ServiceInvokerFacade.getInstance().invokeService(xmlInput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, this.idAplicacion, serviceContent);
		} catch (Exception e) {
			logger.info("No se puede obtener la respuesta de @Firma", e);
			throw new ServiceNotFoundException("No se puede obtener la respuesta de @Firma", e);
		}
		
		Map<String, Object> propertiesResult;
		try {
			propertiesResult = TransformersFacade.getInstance().parseResponse(xmlOutput, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
		} catch (TransformersException e) {
			logger.info("No se puede parsear la respuesta de @Firma", e);
			throw new ServiceException("No se puede parsear la respuesta de @Firma", e);
		}

		//validamos si el resultado ha sido satisfactorio
		String valorResultado = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMayor"));
		String valorResultadoMenor = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMinor"));
		
		//-- Comprobar si la respuesta es v�lida
		int resultado = ValidationResult.RESULT_VALID;
		Date fechaRevocacion = null;
		BasicOCSPResp respuestaOCSP = null;
		int motivoRevocacion = -1;
		
		HashMap<String,Object>[] hmCertVal = (HashMap<String,Object>[]) propertiesResult.get("dss:OptionalOutputs/vr:CertificatePathValidity/vr:PathValidityDetail/vr:CertificateValidity");
		HashMap<String,Object> camposCertificado = (HashMap<String,Object>) propertiesResult.get("dss:OptionalOutputs/afxp:ReadableCertificateInfo");
		
		//-- Obtener la respuesta OCSP
		if (camposCertificado != null && hmCertVal != null) {
			String numeroSerie = (String) camposCertificado.get("numeroSerie");
			String issuer = (String) camposCertificado.get("idEmisor");
			for (HashMap<String,Object> certVal : hmCertVal) {
				if (certVal.get("dss:OptionalOutputs/vr:CertificatePathValidity/vr:PathValidityDetail/vr:CertificateValidity/vr:CertificateIdentifier/ds:X509IssuerName").equals(issuer) &&
						certVal.get("dss:OptionalOutputs/vr:CertificatePathValidity/vr:PathValidityDetail/vr:CertificateValidity/vr:CertificateIdentifier/ds:X509SerialNumber").equals(numeroSerie)) {
					String ocspResponseB64 = (String) certVal.get("dss:OptionalOutputs/vr:CertificatePathValidity/vr:PathValidityDetail/vr:CertificateValidity/vr:CertificateStatus/vr:RevocationEvidence/vr:OCSPValidity/OCSPValue");
					if (ocspResponseB64 != null) {
						try {
							ASN1InputStream inp = new ASN1InputStream(Util.decodeBase64(ocspResponseB64));
							BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(inp.readObject());
							respuestaOCSP = new BasicOCSPResp(basicResp);
							CertificateStatus status = respuestaOCSP.getResponses()[0].getCertStatus();
							if (status instanceof RevokedStatus) {
								RevokedStatus revokedStatus = (RevokedStatus) status;
								fechaRevocacion = revokedStatus.getRevocationTime();
								if (!revokedStatus.hasRevocationReason()) {
									motivoRevocacion = -1;
								} else {
									motivoRevocacion = revokedStatus.getRevocationReason();
								}
							}
						} catch (Exception e) {
							logger.info("No se ha podido leer la respuesta OCSP", e);
						}
					} else {
						logger.info("No existe la respuesta OCSP");
					}
				}
			}
		}
		
		if (valorResultado.equals(ResultProcessIds.SUCESS)) {
			if (valorResultadoMenor.equals(AFIRMA_MINOR_RESULT_CERTIFICATE_REVOKED)) {
				resultado = ValidationResult.RESULT_CERTIFICATE_REVOKED;
			}
		} else {
			logger.info("Resultado: " + propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMessage")));
			if (valorResultado.equals(ResultProcessIds.REQUESTER_ERROR) && valorResultadoMenor.equals(AFIRMA_MINOR_RESULT_CERTIFICATE_NOT_SUPPORTED)) {
				resultado = ValidationResult.RESULT_CERTIFICATE_NOT_BELONGS_TRUSTED_CAS;
			} else {
				resultado = ValidationResult.RESULT_INVALID;
			}
		}
		
		//-- Devolver resultado
		CertificateValidationServiceResult certResult = new CertificateValidationServiceResult(resultado, camposCertificado);
		if (fechaRevocacion != null) {
			certResult.setRevocationDate(fechaRevocacion);
			certResult.setRevocationReason(motivoRevocacion);
		}
		if (respuestaOCSP != null) {
			try {
				ASN1EncodableVector v1 = new ASN1EncodableVector();
				v1.add(new ASN1Enumerated(0));
				
				ASN1EncodableVector v2 = new ASN1EncodableVector();
				ASN1ObjectIdentifier id = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
				v2.add(id);
				v2.add(new DEROctetString(DERSequence.fromByteArray(respuestaOCSP.getEncoded())));
				DERTaggedObject tagged = new DERTaggedObject(true, 0, new DERSequence(v2));
				v1.add(tagged);
				DERSequence seq1 = new DERSequence(v1);
				
				OCSPResp r = new OCSPResp(seq1.getEncoded());
				OCSPResponse ocspResponse = new OCSPResponse(r);
				certResult.setOcspResponse(ocspResponse);
			} catch (Exception e) {
				logger.info("No se ha podido construir la respuesta OCSP");
			}
		}
		
		//-- Certificado (Obtener la clasificaci�n)
		if (propertiesResult.get("dss:OptionalOutputs/vr:VerificationReport/vr:IndividualSignatureReport") != null) {
			Map<String, Object> individualSignatureReport = ((Map<String, Object>[]) propertiesResult.get("dss:OptionalOutputs/vr:VerificationReport/vr:IndividualSignatureReport"))[0];
			if (individualSignatureReport != null) {
				Map<String, Object> certificateInfo = (Map<String, Object>) individualSignatureReport.get("dss:OptionalOutputs/vr:VerificationReport/vr:IndividualSignatureReport/vr:Details/afxp:ReadableCertificateInfo");
				if (certificateInfo != null) {
					try {
						certResult.setCertificateCategory(Integer.parseInt((String)certificateInfo.get("clasificacion")));
					} catch (Exception e) {
						logger.info("La clasificaci�n de certificado devuelta por @Firma no es un entero: " + certificateInfo.get("clasificacion"));
					}
				}
			}
		} else if (camposCertificado.get("clasificacion") != null) {
			try {
				certResult.setCertificateCategory(Integer.parseInt((String)camposCertificado.get("clasificacion")));
			} catch (Exception e) {
				logger.info("La clasificaci�n de certificado devuelta por @Firma no es un entero: " + camposCertificado.get("clasificacion"));
			}
		}
		
		return certResult;
	}
	
	/*
	 * Indica si el certificado es de entidad a partir de la clasificaci�n de @Firma
	 */
	public static boolean isEntidad(int clasificacion) {
		return clasificacion == AFIRMA_CLASIFICACION_PERSONA_JURIDICA || 
				clasificacion == AFIRMA_CLASIFICACION_ENTIDAD || 
				clasificacion == AFIRMA_CLASIFICACION_CUALIFICADO_SELLO || 
				clasificacion == AFIRMA_CLASIFICACION_REPRESENTANTE_CPJ || 
				clasificacion == AFIRMA_CLASIFICACION_REPRESENTANTE_SPJ;
	}

	/*
	 * Indica si el certificado es persona f�sica a partir de la clasificaci�n de @Firma
	 */
	public static boolean isPersonaFisica(int clasificacion) {
		return clasificacion == AFIRMA_CLASIFICACION_PERSONA_FISICA || 
				clasificacion == AFIRMA_CLASIFICACION_EMPLEADO_PUBLICO || 
				clasificacion == AFIRMA_CLASIFICACION_AUTENTICACION || 
				clasificacion == AFIRMA_CLASIFICACION_REPRESENTANTE_CPJ || 
				clasificacion == AFIRMA_CLASIFICACION_REPRESENTANTE_SPJ;
	}


	
	//-- Clases privadas
	
	/**
	 * Clase que requiere ACCVIntegra para obtener los par�metros con los que se realizar�
	 * la llamada.
	 */
	public class ArangiServiceContent implements Afirma5ServiceInvokerContent {
		
		Properties afirmaProperties;
		
		public ArangiServiceContent(String url, String user, String password,
				String configuracionWSS4J) {
			afirmaProperties = new Properties();
			afirmaProperties.put("com.certificatesCache.use","true");
			afirmaProperties.put("com.certificatesCache.entries","2");
			afirmaProperties.put("com.certificatesCache.lifeTime","120");
			afirmaProperties.put("secureMode", configuracionWSS4J==null?"false":"true");
			afirmaProperties.put("endPoint", url);
			afirmaProperties.put("servicePath", "afirmaws/services");
			afirmaProperties.put("callTimeout", "20000");
			if (configuracionWSS4J!=null) {
				afirmaProperties.put("authorizationMethod", "BinarySecurityToken");
				afirmaProperties.put("authorizationMethod.signaturePropFile", configuracionWSS4J);
			} else if (user != null && password != null) {
				afirmaProperties.put("authorizationMethod", "UsernameToken");
				afirmaProperties.put("authorizationMethod.user", user);
				afirmaProperties.put("authorizationMethod.password", password);
			} else {
				afirmaProperties.put("authorizationMethod", "none");
			}
			afirmaProperties.put("response.validate", "false");
			afirmaProperties.put("response.certificateAlias", "DefaultFirma");
		}

		public long getLastModified() {
			return new Date().getTime();
		}

		public Properties getProperties() throws Exception {
			return afirmaProperties;
		}
		
	}

}
