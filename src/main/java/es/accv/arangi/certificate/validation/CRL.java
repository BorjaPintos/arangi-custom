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
package es.accv.arangi.certificate.validation;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509CRL;

import es.accv.arangi.base.exception.certificate.CRLParsingException;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.ConnectionException;
import es.accv.arangi.base.exception.certificate.InvalidCRLException;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para trabajar con las CRLs de las diferentes Autoridades de 
 * Certificación de la ACCV.<br><br>
 * 
 * Ejemplo de uso:<br>
 * <code>
 * 	CRL crl = new CRL (new URL ("http://server/crl"));<br>
 * 	Certificate certificate = new Certificate (new File ("c:/certificates/myCertificate.cer"));<br><br>
 * 
 * 	System.out.println ("Is revoked? " + crl.isRevoked (certificate));<br>
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class CRL extends es.accv.arangi.base.certificate.validation.CRL {

	/**
	 * Obtiene una CRL en base a un array de bytes. Esta CRL no se 
	 * valida. Si se considera que la CRL debería ser válida a día de hoy llamar al 
	 * método {@link #validate(CAList) validate} tras la inicialización.
	 * 
	 * @param bytesCRL Array de bytes que contiene la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el contenido del
	 * 	array de bytes
	 */
	public CRL (byte[] bytesCRL) throws CRLParsingException {
		super(bytesCRL);
	}
	
	/**
	 * Obtiene una CRL en base a un stream de lectura. Esta CRL no se 
	 * valida. Si se considera que la CRL debería ser válida a día de hoy llamar al 
	 * método {@link #validate(CAList) validate} tras la inicialización.
	 * 
	 * @param isCRL Stream de lectura que contiene la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el contenido del
	 * 	stream de lectura
	 */
	public CRL (InputStream isCRL) throws CRLParsingException {
		super (isCRL);
	}
	
	/**
	 * Obtiene una CRL del fichero que se pasa como parámetro. Esta CRL no se 
	 * valida. Si se considera que la CRL debería ser válida a día de hoy llamar al 
	 * método {@link #validate(CAList) validate} tras la inicialización.
	 * 
	 * @param crlFile Fichero que contiene la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el contenido del
	 * 	fichero
	 * @throws FileNotFoundException El fichero no existe
	 */
	public CRL(File crlFile) throws CRLParsingException, FileNotFoundException {
		super(crlFile);
	}

	/**
	 * Obtiene una CRL de la URL que se pasa como parámetro. Comprueba que la CRL es 
	 * válida, si no es así lanza una excepción y no permite que se inicialice este
	 * objeto.
	 * 
	 * @param crlURL URL a una CRL
	 * @throws ConnectionException Problemas de conexión impiden obtener la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el documento que
	 * 	se encuentra en la URL
	 * @throws InvalidCRLException La CRL no es válida
	 * @throws CertificateCANotFoundException No se puede validar la firma porque 
	 * 	en la lista de certificados de las CAs falta alguno de la cadena de
	 * 	confianza y es necesario para la correcta finalización del proceso
	 */
	public CRL(URL crlURL) throws ConnectionException, CRLParsingException, InvalidCRLException, CertificateCANotFoundException {
		super(crlURL, ArangiUtil.getACCVCaList());
	}

	/**
	 * Constructor. El objeto CRL que se pasa como parámetro no se valida. Si se
	 * considera que la CRL debería ser válida a día de hoy llamar al método 
	 * {@link #validate(CAList) validate} tras la inicialización.
	 * 
	 * @param crl CRL a la que envolverá esta clase
	 */
	public CRL(X509CRL crl) {
		super(crl);
	}

	
	
}
