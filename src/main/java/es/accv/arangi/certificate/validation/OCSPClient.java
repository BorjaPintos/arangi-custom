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

import java.net.URL;

import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para validar certificados de la ACCV mediante OCSP.<br><br>
 * 
 * Para validar un certificado:<br><br>
 * <code>
 *  URL url = new URL ("http://server/ocsp");<br>
 * 	OCSPClient ocsp = new OCSPClient (url);<br> 
 * 	Certificate certificate = new Certificate (new File ("c:/certificates/myCertificate.cer"));<br>
 * 	Certificate issuer = new Certificate (new File ("c:/certificates/myCertificateIssuer.cer"));<br><br>
 * 
 * 	int result = ocsp.validate (certificate, issuer);
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class OCSPClient extends	es.accv.arangi.base.certificate.validation.OCSPClient {

	/**
	 * Constructor
	 * 
	 * @param urlOCSP URL al OCSP
	 */
	public OCSPClient(URL urlOCSP) {
		super(urlOCSP);
	}

	
	
}
