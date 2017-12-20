using System;

namespace Org.BouncyCastle.Asn1
{
    /**
     * ASN.1 TaggedObject - in ASN.1 notation this is any object proceeded by
     * a [n] where n is some number - these are assume to follow the construction
     * rules (as with sequences).
     */
    public abstract class Asn1TaggedObject
		: Asn1Object, Asn1TaggedObjectParser
    {
        internal int            tagNo;
//        internal bool           empty;
        internal bool           explicitly = true;
        internal Asn1Encodable  obj;

		static public Asn1TaggedObject GetInstance(
            Asn1TaggedObject	obj,
            bool				explicitly)
        {
            if (explicitly)
            {
                return (Asn1TaggedObject) obj.GetObject();
            }

            throw new ArgumentException("implicitly tagged tagged object");
        }

		static public Asn1TaggedObject GetInstance(
			object obj)
		{
			if (obj == null || obj is Asn1TaggedObject)
			{
				return (Asn1TaggedObject) obj;
			}

			throw new ArgumentException("unknown object in GetInstance");
		}

		/**
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        protected Asn1TaggedObject(
            int             tagNo,
            Asn1Encodable   obj)
        {
            this.explicitly = true;
            this.tagNo = tagNo;
            this.obj = obj;
        }

		/**
         * @param explicitly true if the object is explicitly tagged.
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        protected Asn1TaggedObject(
            bool            explicitly,
            int             tagNo,
            Asn1Encodable   obj)
        {
            this.explicitly = explicitly;
            this.tagNo = tagNo;
            this.obj = obj;
        }

		protected override bool Asn1Equals(
			Asn1Object obj)
        {
			Asn1TaggedObject other = obj as Asn1TaggedObject;

			if (other == null)
				return false;

			return this.tagNo == other.tagNo
//				&& this.empty == other.empty
				&& this.explicitly == other.explicitly
				&& object.Equals(this.GetObject(), other.GetObject());
		}

		protected override int Asn1GetHashCode()
		{
            int code = (int)tagNo;

            if (obj != null)
            {
                code ^= obj.GetHashCode();
            }

            return code;
        }

		public int TagNo
        {
			get { return tagNo; }
        }

		/**
         * return whether or not the object may be explicitly tagged.
         * <p>
         * Note: if the object has been read from an input stream, the only
         * time you can be sure if isExplicit is returning the true state of
         * affairs is if it returns false. An implicitly tagged object may appear
         * to be explicitly tagged, so you need to understand the context under
         * which the reading was done as well, see GetObject below.
         */
        public bool IsExplicit()
        {
            return explicitly;
        }

        public bool IsEmpty()
        {
            return false; //empty;
        }

		/**
         * return whatever was following the tag.
         * <p>
         * Note: tagged objects are generally context dependent if you're
         * trying to extract a tagged object you should be going via the
         * appropriate GetInstance method.
         */
        public Asn1Object GetObject()
        {
            if (obj != null)
            {
                return obj.ToAsn1Object();
            }

			return null;
        }

		/**
		* Return the object held in this tagged object as a parser assuming it has
		* the type of the passed in tag. If the object doesn't have a parser
		* associated with it, the base object is returned.
		*/
		public IAsn1Convertible GetObjectParser(
			int		tag,
			bool	isExplicit)
		{
			if (isExplicit)
			{
				switch (tag)
				{
					case Asn1Tags.Set:
						return Asn1Set.GetInstance(this, isExplicit).Parser;
					case Asn1Tags.Sequence:
						return Asn1Sequence.GetInstance(this, isExplicit).Parser;
					case Asn1Tags.OctetString:
						return Asn1OctetString.GetInstance(this, isExplicit).Parser;
				}

				return GetObject();
			}
			else
			{
				switch (tag)
				{
					case Asn1Tags.Set:
						return Asn1Set.GetInstance(this, isExplicit).Parser;
					case Asn1Tags.Sequence:
						return Asn1Sequence.GetInstance(this, isExplicit).Parser;
					case Asn1Tags.OctetString:
						return Asn1OctetString.GetInstance(this, isExplicit).Parser;
				}
			}

			throw new NotImplementedException("implicit tagging not implemented for tag: " + tag);
		}

		public override string ToString()
		{
			return "[" + tagNo + "]" + obj;
		}
	}
}
