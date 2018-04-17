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
import java.io.InputStream;
import java.security.cert.X509Certificate;

import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.certificate.validation.ValidateCertificate;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;

/**
 * Certificados personales: en principio los de ciudadano, empleado
 * p�blico y DNIe deben cumplir esta especificaci�n
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public abstract class CertificadoPersona extends CertificadoACCV {

	/**
	 * Constructor con un certificado X509Certificate
	 * 
	 * @param certificate Certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPersona(X509Certificate certificate, CAList caList) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(certificate, caList);
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param fileCertificate Fichero que contiene un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 * @throws FileNotFoundException El fichero no existe
	 */
	public CertificadoPersona(File fileCertificate, CAList caList) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
		super(fileCertificate, caList);
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param isCertificate Stream de lectura a un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPersona(InputStream isCertificate, CAList caList) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(isCertificate, caList);
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param contenidoCertificado Contenido de un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPersona(byte[] contenidoCertificado, CAList caList) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, caList);
	}
	
	/**
	 * M�todo que devuelve el nombre del titular del certificado
	 * 
	 * @return Nombre del titular del certificado
	 */
	public abstract String getName ();
	
	/**
	 * M�todo que devuelve el primer apellido del titular del certificado
	 * 
	 * @return Primer apellido del titular del certificado
	 */
	public abstract String getFirstSurname ();
	
	/**
	 * M�todo que devuelve el segundo apellido del titular del certificado
	 * 
	 * @return Segundo apellido del titular del certificado
	 */
	public abstract String getSecondSurname ();
	
	/**
	 * M�todo que devuelve los apellidos del titular del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public abstract String getSurnames ();

	/**
	 * M�todo que devuelve el NIF del titular del certificado
	 * 
	 * @return NIF del titular del certificado
	 */
	public abstract String getNIF ();

}
