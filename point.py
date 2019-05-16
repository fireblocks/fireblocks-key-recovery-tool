from curve import secp256k1


class CurveMismatchError(Exception):
    def __init__(self, curve1, curve2):
        self.msg = 'Tried to add points on two different curves <{}> & <{}>'.format(
            curve1.name, curve2.name)


class Point:
    """Representation of a point on an elliptic curve.

    Attributes:
        |  x (long): The x coordinate of the point.
        |  y (long): The y coordinate of the point.
        |  curve (:class:`Curve`): The curve that the point lies on.
    """

    def __init__(self, x, y, curve=secp256k1):
        """Initialize a point on an elliptic curve.

        The x and y parameters must satisfy the equation :math:`y^2 \equiv x^3 + ax + b \pmod{p}`,
        where a, b, and p are attributes of the curve parameter.

        Args:
            |  x (long): The x coordinate of the point.
            |  y (long): The y coordinate of the point.
            |  curve (:class:`Curve`): The curve that the point lies on.
        """
        if not (x == 0 and y == 1 and curve is None) and not curve.is_point_on_curve((x, y)):
            raise ValueError(
                'coordinates are not on curve <{}>\n\tx={:x}\n\ty={:x}'.format(curve.name, x, y))
        else:
            self.x = x
            self.y = y
            self.curve = curve

    def __str__(self):
        if self == self.IDENTITY_ELEMENT:
            return '<POINT AT INFINITY>'
        else:
            return 'X: 0x{:x}\nY: 0x{:x}\n(On curve <{}>)'.format(self.x, self.y, self.curve.name)

    def __unicode__(self):
        return self.__str__()

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.curve is other.curve

    def __fe_div(self, x, y):
        # self.num and other.num are the actual values
        # self.prime is what we need to mod against
        # use fermat's little theorem:
        # self.num**(p-1) % p == 1
        # this means:
        # 1/n == pow(n, p-2, p)
        return (x * pow(y, self.curve.p - 2, self.curve.p)) % self.curve.p

    def __add__(self, other):
        """Add two points on the same elliptic curve.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve
            | other (:class:`Point`): a point :math:`Q` on the curve

        Returns:
            :class:`Point`: A point :math:`R` such that :math:`R = P + Q`
        """
        if self == self.IDENTITY_ELEMENT:
            return other
        elif other == self.IDENTITY_ELEMENT:
            return self
        elif self.curve is not other.curve:
            raise CurveMismatchError(self.curve, other.curve)
        elif self.x == other.x and self.y != other.y:
            return self.IDENTITY_ELEMENT
        elif self == other and self.y == 0:
            return self.IDENTITY_ELEMENT
        
        if self.x != other.x:
            s = self.__fe_div(other.y - self.y, other.x - self.x)
            x = (s**2 - self.x - other.x) % self.curve.p
            y = (s * (self.x - x) - self.y) % self.curve.p
            return Point(x, y, self.curve)
        
        if self == other:
            s = self.__fe_div(3 * self.x**2 + self.curve.a, 2 * self.y)
            # s = (3 * self.x**2 + self.curve.a) / (2 * self.y)
            x = (s**2 - 2 * self.x) % self.curve.p
            y = (s * (self.x - x) - self.y) % self.curve.p
            return Point(x, y, self.curve)

    def __radd__(self, other):
        """Add two points on the same elliptic curve.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve
            | other (:class:`Point`): a point :math:`Q` on the curve

        Returns:
            :class:`Point`: A point :math:`R` such that :math:`R = P + Q`
        """
        return self.__add__(other)

    def __sub__(self, other):
        """Subtract two points on the same elliptic curve.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve
            | other (:class:`Point`): a point :math:`Q` on the curve

        Returns:
            :class:`Point`: A point :math:`R` such that :math:`R = P - Q`
        """
        if self == other:
            return self.IDENTITY_ELEMENT
        elif other == self.IDENTITY_ELEMENT:
            return self

        negative = Point(other.x, -other.y % other.curve.p, other.curve)
        return self.__add__(negative)

    def __mul__(self, scalar):
        """Multiply a :class:`Point` on an elliptic curve by an integer.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve
            | scalar (long): an integer :math:`d \in \mathbb{Z_q}` where :math:`q` is the order of
                the curve that :math:`P` is on

        Returns:
            :class:`Point`: A point :math:`R` such that :math:`R = P * d`
        """
        try:
            d = int(scalar) % self.curve.q
        except ValueError:
            raise TypeError('Curve point multiplication must be by an integer')
        else:
            if d == 0:
                return self.IDENTITY_ELEMENT

            current = self
            result = self.IDENTITY_ELEMENT
            while d:
                if d & 1:
                    result += current
                current += current
                d >>= 1
            return result

    def __rmul__(self, scalar):
        """Multiply a :class:`Point` on an elliptic curve by an integer.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve
            | other (long): an integer :math:`d \in \mathbb{Z_q}` where :math:`q` is the order of
                the curve that :math:`P` is on

        Returns:
            :class:`Point`: A point :math:`R` such that :math:`R = d * P`
        """
        return self.__mul__(scalar)

    def __neg__(self):
        """Return the negation of a :class:`Point` i.e. the points reflection over the x-axis.

        Args:
            | self (:class:`Point`): a point :math:`P` on the curve

        Returns:
            :class:`Point`: A point :math:`R = (P_x, -P_y)`
        """
        if self == self.IDENTITY_ELEMENT:
            return self

        return Point(self.x, -self.y % self.curve.p, self.curve)

    def serialize(self, compressed = True):
        """Encodes a Point object to a octet string
        """

        if self == self.IDENTITY_ELEMENT:
            return "00"

        if compressed:
            if self.y % 2:
                prefix = "03"
            else:
                prefix = "02"

            return prefix + hex(self.x)[2:]
        else:
            return "04" + hex(self.x)[2:] + hex(self.y)[2:]
    
    @staticmethod
    def deserialize(pointStr, curve=secp256k1):
        """Return a :class:`Point` represented by the string pointStr

        Args:
            | pointStr (:class:`String`): a string representation of the point
            | curve (:class:`Curve`): The curve that the point lies on.

        Returns:
            :class:`Point`: A point
        """

        if pointStr == "00":
            return Point.IDENTITY_ELEMENT

        if pointStr.startswith("04") and len(pointStr) == 130:
            return Point(int(pointStr[2:66], 16), int(pointStr[66:], 16), curve)

        if (pointStr.startswith("02") or pointStr.startswith("03")) and len(pointStr) == 66:
            even = pointStr.startswith("02")
            x = int(pointStr[2:], 16)
            y_square = (pow(x, 3, curve.p)  + curve.a * x + curve.b) % curve.p
            y = pow(y_square, (curve.p + 1) // 4, curve.p)
            if (even and y & 1) or (not even and not y & 1):
                y = -y % curve.p
            return Point(x, y, curve)
        raise Exception("invalid format")


Point.IDENTITY_ELEMENT = Point(0, 1, curve=None)  # also known as the point at infinity
