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
 * Certificaci�n de la ACCV.<br><br>
 * 
 * Ejemplo de uso:<br>
 * <code>
 * 	CRL crl = new CRL (new URL ("http://server/crl"));<br>
 * 	Certificate certificate = new Certificate (new File ("c:/certificates/myCertificate.cer"));<br><br>
 * 
 * 	System.out.println ("Is revoked? " + crl.isRevoked (certificate));<br>
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CRL extends es.accv.arangi.base.certificate.validation.CRL {

	/**
	 * Obtiene una CRL en base a un array de bytes. Esta CRL no se 
	 * valida. Si se considera que la CRL deber�a ser v�lida a d�a de hoy llamar al 
	 * m�todo {@link #validate(CAList) validate} tras la inicializaci�n.
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
	 * valida. Si se considera que la CRL deber�a ser v�lida a d�a de hoy llamar al 
	 * m�todo {@link #validate(CAList) validate} tras la inicializaci�n.
	 * 
	 * @param isCRL Stream de lectura que contiene la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el contenido del
	 * 	stream de lectura
	 */
	public CRL (InputStream isCRL) throws CRLParsingException {
		super (isCRL);
	}
	
	/**
	 * Obtiene una CRL del fichero que se pasa como par�metro. Esta CRL no se 
	 * valida. Si se considera que la CRL deber�a ser v�lida a d�a de hoy llamar al 
	 * m�todo {@link #validate(CAList) validate} tras la inicializaci�n.
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
	 * Obtiene una CRL de la URL que se pasa como par�metro. Comprueba que la CRL es 
	 * v�lida, si no es as� lanza una excepci�n y no permite que se inicialice este
	 * objeto.
	 * 
	 * @param crlURL URL a una CRL
	 * @throws ConnectionException Problemas de conexi�n impiden obtener la CRL
	 * @throws CRLParsingException No es posible parsear como CRL el documento que
	 * 	se encuentra en la URL
	 * @throws InvalidCRLException La CRL no es v�lida
	 * @throws CertificateCANotFoundException No se puede validar la firma porque 
	 * 	en la lista de certificados de las CAs falta alguno de la cadena de
	 * 	confianza y es necesario para la correcta finalizaci�n del proceso
	 */
	public CRL(URL crlURL) throws ConnectionException, CRLParsingException, InvalidCRLException, CertificateCANotFoundException {
		super(crlURL, ArangiUtil.getACCVCaList());
	}

	/**
	 * Constructor. El objeto CRL que se pasa como par�metro no se valida. Si se
	 * considera que la CRL deber�a ser v�lida a d�a de hoy llamar al m�todo 
	 * {@link #validate(CAList) validate} tras la inicializaci�n.
	 * 
	 * @param crl CRL a la que envolver� esta clase
	 */
	public CRL(X509CRL crl) {
		super(crl);
	}

	
	
}
