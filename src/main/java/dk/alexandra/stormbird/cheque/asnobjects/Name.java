/**
 * This file was generated by the Objective Systems ASN1C Compiler
 * (http://www.obj-sys.com).  Version: 7.4.2, Date: 22-Jul-2020.
 */
package dk.alexandra.stormbird.cheque.asnobjects;

import com.objsys.asn1j.runtime.*;

public class Name extends Asn1Choice {
   private static final long serialVersionUID = 55;
   static {
      _setKey (_InformationFrameworkRtkey._rtkey);
      Asn1Type._setLicLocation(_InformationFrameworkRtkey._licLocation);
   }

   public String getAsn1TypeName()  {
      return "Name";
   }

   // Choice element identifier constants
   public final static byte _NULL_ = 1;
   public final static byte _RDNSEQUENCE = 2;

   public Name () {
      super();
   }

   public Name (byte choiceId_, Asn1Type element_) {
      super();
      setElement (choiceId_, element_);
   }

   public String getElemName () {
      switch (choiceID) {
      case _NULL_: return "null_";
      case _RDNSEQUENCE: return "rdnSequence";
      default: return "UNDEFINED";
      }
   }

   public void set_null_ () {
      setElement (_NULL_, Asn1Null.NULL_VALUE);
   }

   public void set_rdnSequence (RDNSequence value) {
      setElement (_RDNSEQUENCE, value);
   }

   public void decode
      (Asn1BerDecodeBuffer buffer, boolean explicit, int implicitLength)
      throws Asn1Exception, java.io.IOException
   {
      int llen = implicitLength;

      // decode CHOICE

      Asn1Tag tag = new Asn1Tag ();
      buffer.mark (8);
      int len = buffer.decodeTagAndLength (tag);
      final int choiceLen = len;

      int offset = buffer.getByteCount(), declen;

      if (tag.equals (Asn1Tag.UNIV, Asn1Tag.PRIM, 5))
      {
         buffer.reset();
         Asn1Null lnull__;
         buffer.getContext().eventDispatcher.startElement("null_", -1);

         lnull__ = new Asn1Null();
         lnull__.decode (buffer, true, len);

         buffer.getContext().eventDispatcher.endElement("null_", -1);
         setElement (_NULL_, lnull__);
      }
      else if (tag.equals (Asn1Tag.UNIV, Asn1Tag.CONS, 16))
      {
         buffer.reset();
         RDNSequence lrdnSequence_;
         buffer.getContext().eventDispatcher.startElement("rdnSequence", -1);

         lrdnSequence_ = new RDNSequence();
         lrdnSequence_.decode (buffer, true, len);

         buffer.getContext().eventDispatcher.endElement("rdnSequence", -1);
         setElement (_RDNSEQUENCE, lrdnSequence_);
      }
      else {
         throw new Asn1InvalidChoiceOptionException (buffer, tag);
      }

      declen = buffer.getByteCount() - offset;
      if (choiceLen != Asn1Status.INDEFLEN && choiceLen != declen)
         throw new Asn1InvalidLengthException();
   }

   public int encode (Asn1BerEncodeBuffer buffer, boolean explicit)
      throws Asn1Exception
   {
      int _aal = 0, len;
      switch (choiceID) {
      // encode null_
      case _NULL_:
         Asn1Null lnull__ = (Asn1Null) getElement();
         buffer.getContext().eventDispatcher.startElement("null_", -1);

         len = lnull__.encode (buffer, true);
         _aal += len;

         buffer.getContext().eventDispatcher.endElement("null_", -1);
         break;

      // encode rdnSequence
      case _RDNSEQUENCE:
         RDNSequence lrdnSequence_ = (RDNSequence) getElement();
         buffer.getContext().eventDispatcher.startElement("rdnSequence", -1);

         len = lrdnSequence_.encode (buffer, true);
         _aal += len;

         buffer.getContext().eventDispatcher.endElement("rdnSequence", -1);
         break;

      default:
         throw new Asn1InvalidChoiceOptionException();
      }

      return _aal;
   }

   public void print (java.io.PrintWriter _out, String _varName, int _level)
   {
      indent (_out, _level);
      _out.println (_varName + " {");
      if (element != null) {
         element.print (_out, getElemName(), _level+1);
      }
      indent (_out, _level);
      _out.println ("}");
   }

}