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
package es.accv.arangi.util.smime;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.mail.smime.CMSProcessableBodyPart;

/**
 * Esta clase se copia directamente de la antigua librer�a IDEAS. Su funci�n es
 * la de permitir la validaci�n de los tokens de validaci�n de la ACCV, ya que
 * las primeras versiones de Bouncy Castle que se utilizaron constru�an los 
 * S-MIMEs de un modo incompatible con las nuevas versiones.
 */
public class SMIMESigned extends CMSSignedData {

  
  Object                  message;
  MimeBodyPart            content;

  static
  {
      MailcapCommandMap mc = (MailcapCommandMap)CommandMap.getDefaultCommandMap();

      mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
      mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
      mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
      mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
      mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
      
      CommandMap.setDefaultCommandMap(mc);
  }
  

  private static InputStream getInputStream(
      Part    bodyPart)
      throws MessagingException
  {
      try
      {
          if (bodyPart.isMimeType("multipart/signed"))
          {
              throw new MessagingException("attempt to create signed data object from multipart content - use MimeMultipart constructor.");
          }
          
          return bodyPart.getInputStream();
      }
      catch (IOException e)
      {
          throw new MessagingException("can't extract input stream: " + e);
      }
  }

  
  

  /**
   * @param message
   * @throws MessagingException
   * @throws CMSException
   */
  public SMIMESigned(MimeMultipart message) throws MessagingException, CMSException {
    super(new CMSProcessableBodyPart(message.getBodyPart(0)), getInputStream(message.getBodyPart(1)));

    this.message = message;
    this.content = (MimeBodyPart)message.getBodyPart(0);
  }



  /**
   * return the content that was signed.
   */
  public MimeBodyPart getContent() {
    return content;
  }


  /**
   * Return the content that was signed as a mime message.
   * 
   * @param session
   * @return a MimeMessage holding the content.
   * @throws MessagingException
   */
  public MimeMessage getContentAsMimeMessage(Session session) throws MessagingException, IOException {
    Object content = getSignedContent().getContent();
    byte[] contentBytes = null;

    if (content instanceof byte[]) {
      contentBytes = (byte[]) content;
    } else if (content instanceof MimePart) {
      MimePart part = (MimePart) content;
      ByteArrayOutputStream out;

      if (part.getSize() > 0) {
        out = new ByteArrayOutputStream(part.getSize());
      } else {
        out = new ByteArrayOutputStream();
      }

      part.writeTo(out);
      contentBytes = out.toByteArray();
    } else {
      String type = "<null>";
      if (content != null) {
        type = content.getClass().getName();
      }

      throw new MessagingException("Could not transfrom content of type " + type + " into MimeMessage.");
    }

    if (contentBytes != null) {
      ByteArrayInputStream in = new ByteArrayInputStream(contentBytes);

      return new MimeMessage(session, in);
    }

    return null;
  }


  /**
   * return the content that was signed - depending on whether this was
   * unencapsulated or not it will return a MimeMultipart or a MimeBodyPart
   */
  public Object getContentWithSignature() {
    return message;
  }


}
