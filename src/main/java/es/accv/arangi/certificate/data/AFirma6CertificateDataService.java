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
package es.accv.arangi.certificate.data;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.data.CertificateDataService;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.validation.ServiceException;
import es.accv.arangi.base.exception.certificate.validation.ServiceNotFoundException;
import es.accv.arangi.base.util.Util;
import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerContent;
import es.gob.afirma.afirma5ServiceInvoker.Afirma5ServiceInvokerFacade;
import es.gob.afirma.transformers.TransformersConstants;
import es.gob.afirma.transformers.TransformersException;
import es.gob.afirma.transformers.TransformersFacade;
import es.gob.afirma.utils.DSSConstants.DSSTagsRequest;
import es.gob.afirma.utils.DSSConstants.ResultProcessIds;
import es.gob.afirma.utils.GeneralConstants;

/**
 * Clase que implementa la obtención de datos mediante llamadas a los 
 * servicios web DSS de &#64;Firma6.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José Manuel Gutiérrez Núñez</a>
 *
 */
public class AFirma6CertificateDataService implements CertificateDataService {

	/*
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(AFirma6CertificateDataService.class);
	
	/*
	 * URL de acceso a los servicios web de &#64;Firma
	 */
	private String url;
	
	/*
	 * Identificador de la aplicación en &#64;Firma
	 */
	private String idAplicacion;
	
	/*
	 * Usuario 
	 */
	private String user;
	
	/*
	 * Contraseña
	 */
	private String password;
	
	/*
	 * Fichero de acceso a almacén de claves (WSS4J)
	 */
	private String configuracionWSS4J;
	
	//-- Constructores	
	
	/**
	 * Constructor por defecto: si se usa este constructor será necesario inicializar
	 * el objeto.
	 */
	public AFirma6CertificateDataService() {
		super();
	}
	
	/**
	 * Constructor en el que pasar la información necesaria para crear 
	 * este objeto.
	 * 
	 * @param url URL al servico web de &#64;Firma. Los posibles valores se pueden
	 * 	encontrar en los campos estáticos de esta clase PRODUCTION_URL y
	 *  TEST_URL.
	 * @param idAplicacion ID de su aplicación. Este valor se le entregó en
	 * 	el momento en que su aplicación fue dada de alta en la plataforma
	 * @param user Nombre de usuario para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contraseña.
	 * @param password Contraseña para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contraseña.
	 * @param configuracionWSS4J Fichero que contiene la información de acceso al
	 * 	certificado que firmará las peticiones que se envían a @Firma 
	 */
	public AFirma6CertificateDataService(String url, String idAplicacion, String user,
			String password, String configuracionWSS4J) {
		super();
		initialize(url, idAplicacion, user, password, configuracionWSS4J);
	}

	/**
	 * Inicializa el objeto
	 * 
	 * @param url URL al servico web de &#64;Firma. Los posibles valores se pueden
	 * 	encontrar en los campos estáticos de esta clase PRODUCTION_URL y
	 *  TEST_URL.
	 * @param idAplicacion ID de su aplicación. Este valor se le entregó en
	 * 	el momento en que su aplicación fue dada de alta en la plataforma
	 * @param user Nombre de usuario para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contraseña.
	 * @param password Contraseña para el caso en que se deba realizar la
	 * 	llamada securizada mediante usuario y contraseña.
	 * @param configuracionWSS4J Fichero que contiene la información de acceso al
	 * 	certificado que firmará las peticiones que se envían a @Firma 
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
	 * Obtiene los datos de un certificado mediante una llamada a un servicio externo.
	 * 
	 * @param certificate Certificado 
	 * @param extraParams Parámetros extra por si fueran necesarios para 
	 * 	realizar la obtención
	 * @return Map con los valores obtenidos del certificado
	 * @throws ServiceNotFoundException El servicio no se encuentra disponible
	 * @throws ServiceException La llamada al servicio devuelve un error
	 */
	public Map<String, String> getData(Certificate certificate,
			Map<String, Object> extraParams) throws ServiceNotFoundException,
			ServiceException {
		logger.debug("[AFirmaCertificateValidationService.validate]::Entrada::" + Arrays.asList(new Object[] { certificate, extraParams }));
		
		//-- Pasar los parámetros a un properties
		ArangiServiceContent serviceContent = new ArangiServiceContent(url, user, password, configuracionWSS4J);
		
		Map<String, Object> inParams = new HashMap<String, Object>();

		inParams.put(DSSTagsRequest.CLAIMED_IDENTITY, this.idAplicacion);
		inParams.put(DSSTagsRequest.INCLUDE_CERTIFICATE, "true");
		inParams.put(DSSTagsRequest.RETURN_READABLE_CERT_INFO, "");
		try {
			inParams.put(DSSTagsRequest.X509_CERTIFICATE, Util.encodeBase64(certificate.toDER()));
		} catch (NormalizeCertificateException e) {
			//-- El certificado ya se normalizó al entrar, no se dará el error
			logger.info ("[AFirmaCertificateValidationService.validate]", e);
		}
		
		String xmlInput;
		try {
			xmlInput = TransformersFacade.getInstance().generateXml(inParams, GeneralConstants.DSS_AFIRMA_VERIFY_CERTIFICATE_REQUEST, GeneralConstants.DSS_AFIRMA_VERIFY_METHOD, TransformersConstants.VERSION_10);
		} catch (TransformersException e) {
			logger.info("No se puede crear la petición para @Firma", e);
			throw new ServiceException("No se puede crear la petición para @Firma", e);
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
		String valorResultadoTexto = (String) propertiesResult.get(TransformersFacade.getInstance().getParserParameterValue("ResultMessage"));
		
		if (!valorResultado.equals(ResultProcessIds.SUCESS)) {
			logger.info("[AFirmaCertificateValidationService.validate]::La respuesta de @Firma es de error");
			throw new ServiceException(valorResultadoMenor + " - " + valorResultadoTexto);
		}
		
		return (HashMap<String, String>) propertiesResult.get("dss:OptionalOutputs/afxp:ReadableCertificateInfo");
	}

	//-- Clases privadas
	
	/**
	 * Clase que requiere ACCVIntegra para obtener los parámetros con los que se realizará
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
