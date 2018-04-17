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
 *  * 17-abr-2018 - File: - CustomAliases.java
 * 	Author: Borja Pintos Castro - borjapintoscastro@gmail.com
 * 
 */
package es.accv.arangi.device;

/**
 * The Class CustomAliases.
 */
public class CustomAliases {

	/** The signature alias. */
	private String signatureAlias;
	
	/** The cipher alias. */
	private String cipherAlias;
	
	/** The authentication alias. */
	private String authenticationAlias;

	/**
	 * Gets the signature alias.
	 *
	 * @return the signature alias
	 */
	public String getSignatureAlias() {
		return signatureAlias;
	}

	/**
	 * Sets the signature alias.
	 *
	 * @param signatureAlias the new signature alias
	 */
	public void setSignatureAlias(String signatureAlias) {
		this.signatureAlias = signatureAlias;
	}

	/**
	 * Gets the cipher alias.
	 *
	 * @return the cipher alias
	 */
	public String getCipherAlias() {
		return cipherAlias;
	}

	/**
	 * Sets the cipher alias.
	 *
	 * @param cipherAlias the new cipher alias
	 */
	public void setCipherAlias(String cipherAlias) {
		this.cipherAlias = cipherAlias;
	}

	/**
	 * Gets the authentication alias.
	 *
	 * @return the authentication alias
	 */
	public String getAuthenticationAlias() {
		return authenticationAlias;
	}

	/**
	 * Sets the authentication alias.
	 *
	 * @param authenticationAlias the new authentication alias
	 */
	public void setAuthenticationAlias(String authenticationAlias) {
		this.authenticationAlias = authenticationAlias;
	}
	
	
	
}

