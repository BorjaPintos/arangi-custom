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
package es.accv.arangi.certificate;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Map.Entry;

import org.apache.log4j.Logger;

import es.accv.arangi.base.ArangiObject;
import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.certificate.validation.ValidateCertificate;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.util.Util;

/**
 * Los diferentes certificados que implementan la clase es.accv.arangi.base.certificate
 * registran sus pol�ticas en esta clase, de forma que cuando se llama al m�todo
 * getInstance pas�ndole un certificado x.509v3 la clase devolver� un objeto que se adec�e
 * a la pol�tica del certificado pasado.<br><br>
 * 
 * Ejemplo de uso: <br><br>
 * 
 * <code>
 * 	X509Certificate x509Certificate = Util.getCertificate(new File ("/certificates/cert.cer"));<br>
 * 	ValidateCertificate cert = CertificateFactory.getInstance(x509Certificate);<br>
 * 	if (cert instanceof CertificadoCiudadano) {<br>
 * 	&nbsp;&nbsp;CertificadoCiudadano cCiudadano = (CertificadoCiudadano) cert;<br>
 * 	&nbsp;&nbsp;System.out.println ("Nombre ciudadano: " + cCiudadano.getName());<br>
 * 	}
 * </code><br><br>
 * 
 * En ciertas situaciones se quiere trabajar con certificados de alg�n otro prestador y ser�a
 * deseable que las llamadas al m�todo getInstance() pudiesen devolver clases que tratasen la
 * informaci�n contenida en estos certificados. Los pasos a seguir son los siguientes:<br><br>
 * 
 * <ol>
 * 	<li>Programar la clase que trate con la informaci�n del nuevo tipo de certificado. Dicha 
 *  clase ha de ser hija de <code>ValidateCertificate</code> o de alguno de las clases para 
 *  certificados de Arang�. Debe contener un constructor con un par�metro de tipo {@link CertificadoDesconocido CertificadoDesconocido}.
 *  Hay un ejemplo m�s abajo. 
 *  </li>
 * 	<li>Crear un paquete <code>es.accv.arangi.ext.certificate</code> y en �l generar un fichero
 * 	llamado <i>certificates.properties</i>. En dicho archivo de propiedades se pueden asociar
 *  pol�ticas de certificados con las clases que se quiere utilizar para tratarlos.</li>
 * 	<li>Llamar a los m�todos <code>getInstance()</code> con un {@link CAList CAList} que contenga
 * 	los certificados de la cadena de confianza del nuevo tipo de certificado.</li>
 * </ol><br><br>
 * 
 * Ejemplo de la clase:<br><br>
 * 
 * <code>
 * public class CertificadoPrueba extends CertificadoPersona {<br><br>
 * 
 * public CertificadoPrueba (CertificadoDesconocido certificado) throws CertificateCANotFoundException, NormalizeCertificateException {<br>
 *	super(certificado.toX509Certificate(), certificado.getCertificationChainAsCAList());<br>
 * }<br>
 * ...
 * </code><br><br>
 * 
 * Ejemplo de propiedad:<br><br>
 * 
 * 1.3.6.1.4.1.17345.10.1=es.accv.arangi.ext.certificate.CertificadoPrueba
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificateFactory {
	
	/**
	 * Constante con el path dentro del classpath al fichero de propiedades con la
	 * informaci�n de certificados que no existen en Arang�.
	 */
	public static final String EXTRA_CERTIFICATES_PROPERTIES_PATH = "es/accv/arangi/ext/certificate/certificates.properties";

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificateFactory.class);

	/*
	 * Lista que contiene todos los certificados registrados
	 */
	private static List lCertificateTypes = new ArrayList ();
	
	// Carga la lista de certificados y tipos
	static {
		//-- Por si acaso se adelanta al objeto ArangiObject, insertar el proveedor
		Util.setProvider (ArangiObject.CRYPTOGRAPHIC_PROVIDER_NAME, ArangiObject.CRYPTOGRAPHIC_PROVIDER);
		
		//-- A�adir el certificado de ciudadano a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoCiudadano.getBasePolicies(), CertificadoCiudadano.class);
		
		//-- A�adir el certificado de empleado p�blico a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoEmpleadoPublico.getBasePolicies(), CertificadoEmpleadoPublico.class);
		
		//-- A�adir el certificado de pertenencia a empresa a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoPertenenciaEmpresa.getBasePolicies(), CertificadoPertenenciaEmpresa.class);
		
		//-- A�adir el certificado de seud�nimo a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoSeudonimo.getBasePolicies(), CertificadoSeudonimo.class);
		
		//-- A�adir el certificado de entidad a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoEntidad.getBasePolicies(), CertificadoEntidad.class);
		
		//-- A�adir el certificado de representante a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoRepresentante.getBasePolicies(), CertificadoRepresentante.class);
		
		//-- A�adir el certificado de aplicacion a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoAplicacion.getBasePolicies(), CertificadoAplicacion.class);
		
		//-- A�adir el certificado de sede electr�nica a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoSede.getBasePolicies(), CertificadoSede.class);
		
		//-- A�adir el certificado de sello de �rgano a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoSello.getBasePolicies(), CertificadoSello.class);

		//-- A�adir el certificado del DNIe a la lista de tratables por la factory
		CertificateFactory.addCertificateTypes(CertificadoDNIe.getBasePolicies(), CertificadoDNIe.class);
	}
	
	/**
	 * M�todo al que llamar�n los distintos certificados para registrarse
	 * 
	 * @param policies Pol�ticas de los certificados
	 * @param certificateClass Clase del certificado (ha de ser una subclase de es.accv.arangi.base.certificate.Certificate)
	 */
	public static void addCertificateTypes (String [] policies, Class certificateClass) {
		logger.debug ("[CertificateFactory.addCertificateType]::Registrando pol�ticas " + policies + " para la clase " + certificateClass);
		
		//-- La clase debe ser hija de ValidateCertificate
		if (certificateClass.isAssignableFrom(ValidateCertificate.class)) {
			logger.info ("[CertificateFactory.addCertificateType]::La clase " + certificateClass + " no es una subclase de es.accv.arangi.base.certificate.Certificate");
			return;
		}
		
		//-- A�adir elementos a la lista
		for (int i = 0; i < policies.length; i++) {
			lCertificateTypes.add(new CertificateFactory().new CertificateElement (policies[i], certificateClass));
		}
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. S�lo busca las clases asociadas a los tipos de 
	 * certificado definidos en la librer�a Arang�.
	 * 
	 * @param certificateFile Fichero que contiene un certificado en formato X.509v3
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 * @throws FileNotFoundException El fichero no existe
	 */
	public static ValidateCertificate getInstance (File certificateFile) throws NormalizeCertificateException, FileNotFoundException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (certificateFile);
		
		//-- Llamar a getInstance
		return getInstance(certificate);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. S�lo busca las clases asociadas a los tipos de 
	 * certificado definidos en la librer�a Arang�.
	 * 
	 * @param isCertificate Stream de lectua a un certificado en formato X.509v3
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (InputStream isCertificate) throws NormalizeCertificateException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (isCertificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. S�lo busca las clases asociadas a los tipos de 
	 * certificado definidos en la librer�a Arang�.
	 * 
	 * @param bCertificate Array de bytes de un certificado en formato X.509v3
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (byte[] bCertificate) throws NormalizeCertificateException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (bCertificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. S�lo busca las clases asociadas a los tipos de 
	 * certificado definidos en la librer�a Arang�.
	 * 
	 * @param x509Certificate Certificado en formato X.509
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (X509Certificate x509Certificate) throws NormalizeCertificateException {
		//-- Obtener la pol�tica del certificado
		Certificate certificate = new Certificate (x509Certificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. S�lo busca las clases asociadas a los tipos de 
	 * certificado definidos en la librer�a Arang�.
	 * 
	 * @param certificate Certificado en formato X.509
	 * @return Instancia de certificado
	 */
	public static ValidateCertificate getInstance (Certificate certificate) {
		logger.debug ("[CertificateFactory.getInstance]::Obteniendo un certificado para \n" + (certificate==null?"null":certificate.getCommonName()));
		
		//-- Obtener la pol�tica del certificado
		List<String> policies = certificate.getPolicyOIDs();
		if (policies.isEmpty()) {
			return null;
		}
		
		//-- Iterar sobre la lista
		for (Iterator iterator = lCertificateTypes.iterator(); iterator.hasNext();) {
			CertificateFactory.CertificateElement element = (CertificateFactory.CertificateElement) iterator.next();
			for (String policy : policies) {
				if (policy.startsWith(element.getPolicy())) {
					logger.debug ("[CertificateFactory.getInstance]::Obtenido un certificado para la pol�tica " + policy);
					try {
						return (ValidateCertificate) element.getCertificateClass().getConstructor(new Class[] { X509Certificate.class }).newInstance(new Object[] { certificate.toX509Certificate() });
					} catch (Exception e) {
						logger.info("[CertificateFactory.getInstance]::Error obteniendo una instancia de la clase " + element.getCertificateClass(), e);
					} 
				}
			}
		}
		
		logger.debug("[CertificateFactory.getInstance]::No se ha podido instanciar ninguna clase para las pol�ticas " + policies);
		return null;
		
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. Busca en primer lugar en las clases asociadas a 
	 * los tipos de certificado definidos en la librer�a Arang�. Si no encuentra
	 * una clase que trate con el tipo de certificado buscar� seg�n lo indicado
	 * en el javadoc inicial de esta clase.
	 * 
	 * @param certificateFile Fichero que contiene un certificado en formato X.509v3
	 * @param caList Lista de certificados de CA
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 * @throws FileNotFoundException El fichero no existe
	 */
	public static ValidateCertificate getInstance (File certificateFile, CAList caList) throws NormalizeCertificateException, FileNotFoundException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (certificateFile);
		
		//-- Llamar a getInstance
		return getInstance(certificate, caList);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. Busca en primer lugar en las clases asociadas a 
	 * los tipos de certificado definidos en la librer�a Arang�. Si no encuentra
	 * una clase que trate con el tipo de certificado buscar� seg�n lo indicado
	 * en el javadoc inicial de esta clase.
	 * 
	 * @param isCertificate Stream de lectura a un certificado en formato X.509v3
	 * @param caList Lista de certificados de CA
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (InputStream isCertificate, CAList caList) throws NormalizeCertificateException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (isCertificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate, caList);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. Busca en primer lugar en las clases asociadas a 
	 * los tipos de certificado definidos en la librer�a Arang�. Si no encuentra
	 * una clase que trate con el tipo de certificado buscar� seg�n lo indicado
	 * en el javadoc inicial de esta clase.
	 * 
	 * @param bCertificate Array de bytes de un certificado en formato X.509v3
	 * @param caList Lista de certificados de CA
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (byte[] bCertificate, CAList caList) throws NormalizeCertificateException {
		//-- obtener un certificate
		Certificate certificate = new Certificate (bCertificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate, caList);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. Busca en primer lugar en las clases asociadas a 
	 * los tipos de certificado definidos en la librer�a Arang�. Si no encuentra
	 * una clase que trate con el tipo de certificado buscar� seg�n lo indicado
	 * en el javadoc inicial de esta clase.
	 * 
	 * @param x509Certificate Certificado en formato X.509
	 * @param caList Lista de certificados de CA
	 * @return Instancia de certificado
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato del
	 * 	proveedor criptogr�fico de Arangi
	 */
	public static ValidateCertificate getInstance (X509Certificate x509Certificate, CAList caList) throws NormalizeCertificateException {
		//-- Obtener la pol�tica del certificado
		Certificate certificate = new Certificate (x509Certificate);
		
		//-- Llamar a getInstance
		return getInstance(certificate, caList);
	}
	
	/**
	 * Obtiene una instancia certificado en base a la pol�tica del certificado que 
	 * se le pasa como par�metro. Busca en primer lugar en las clases asociadas a 
	 * los tipos de certificado definidos en la librer�a Arang�. Si no encuentra
	 * una clase que trate con el tipo de certificado buscar� seg�n lo indicado
	 * en el javadoc inicial de esta clase.
	 * 
	 * @param certificate Certificado en formato X.509
	 * @param caList Lista de certificados de CA
	 * @return Instancia de certificado
	 */
	public static ValidateCertificate getInstance (Certificate certificate, CAList caList) {
		logger.debug ("[CertificateFactory.getInstance]::Obteniendo un certificado para \n" + (certificate==null?"null":certificate.getCommonName()));
		
		//-- Obtener un certificado de los tratados por Arang�
		ValidateCertificate validateCertificate = getInstance(certificate);
		if (validateCertificate != null) {
			logger.debug("[CertificateFactory.getInstance]::El certificado pasado es de los tratados por Arang�");
			return validateCertificate;
		}
		
		//-- El certificado no es de los tratados por la ACCV. Lo inicializamos como un
		//-- certificado desconocido.
		try {
			validateCertificate = new CertificadoDesconocido(certificate.toX509Certificate(), caList);
		} catch (CertificateCANotFoundException e) {
			logger.debug("[CertificateFactory.getInstance]::El certificado pasado no pertenece a ninguna de las CAs de CAList");
			return null;
		} catch (NormalizeCertificateException e) {
			//-- No se dar� porque ya ven�a de un Certificate de Arang�
			return null;
		}
		
		//-- Mediante introspecci�n intentar obtener un objeto certificado de un tipo
		//-- concreto. Para ello se busca un fichero de propiedades que relaciona el
		//-- OID de la pol�tica con la clase que tratar� ese tipo de ficheros.
		Properties properties = null;
		try {
			InputStream is = new CertificateFactory().getClass().getClassLoader().getResourceAsStream(EXTRA_CERTIFICATES_PROPERTIES_PATH);
			if (is != null) {
				properties = new Properties ();
				properties.load(is);
			} 
		} catch (IOException e) {
			// No existe el fichero.
			logger.debug("[CertificateFactory.getInstance]::No existe o no se puede leer el fichero de propiedades en " + EXTRA_CERTIFICATES_PROPERTIES_PATH);
		}
		
		if (properties != null) {
			List<String> policies = certificate.getPolicyOIDs();
			logger.debug("[CertificateFactory.getInstance]::Los OIDs de la pol�tica del certificado es: " + policies);
			if (!policies.isEmpty()) {
				for (Iterator<Entry<Object, Object>> iterator = properties.entrySet().iterator(); iterator.hasNext();) {
					Entry<Object, Object> entry = iterator.next();
					for(String policy : policies) {
						if (policy.startsWith((String)entry.getKey())) {
							String className = (String)entry.getValue();
							try {
								validateCertificate = (ValidateCertificate) Class.forName(className).getConstructor(new Class[] { CertificadoDesconocido.class }).newInstance(new Object[] { validateCertificate });
							} catch (Exception e) {
								logger.info("[CertificateFactory.getInstance]::No ha sido posible inicializar un objeto de la clase " + className, e);
							} 
							logger.debug("[CertificateFactory.getInstance]::El certificado pasado tiene una clase externa que puede tratarlo pero no puede ser instanciada");
						}
					}
				}
			}
		}
		
		logger.debug ("[CertificateFactory.getInstance]::El certificado pasado no pertenece a los tratados por Arang� pero si a una de las CAs de CAList");
		return validateCertificate;
		
	}
	
	/*
	 * Clase que representa cada elemento de la lista de certificados
	 */
	private class CertificateElement {
		
		String policy;
		Class certificateClass;
		
		public CertificateElement(String policy, Class certificateClass) {
			super();
			this.policy = policy;
			this.certificateClass = certificateClass;
		}

		public String getPolicy() {
			return policy;
		}

		public void setPolicy(String policy) {
			this.policy = policy;
		}

		public Class getCertificateClass() {
			return certificateClass;
		}

		public void setCertificateClass(Class certificateClass) {
			this.certificateClass = certificateClass;
		}
		
		
	}
	
}
