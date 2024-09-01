using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.NET.Tests;

[TestClass]
public class AnagramHelperTests
{
    [TestMethod]
    public void AnagramSwap_ShouldSwapStringCorrectly()
    {
        // Arrange
        string input = "abcdefgh";
        string expectedSwapped = "efghabcd";

        // Act
        string swapped = AnagramHelper.AnagramSwap(input);

        // Assert
        Assert.AreEqual(expectedSwapped, swapped);
    }

    [TestMethod]
    public void AnagramRestore_ShouldRestoreOriginalString()
    {
        // Arrange
        string original = "abcdefgh";
        string swapped = AnagramHelper.AnagramSwap(original);

        // Act
        string restored = AnagramHelper.AnagramRestore(swapped);

        // Assert
        Assert.AreEqual(original, restored);
    }

    [TestMethod]
    public void AnagramSwap_ShouldHandleEmptyString()
    {
        // Arrange
        string input = "";
        string expectedSwapped = "";

        // Act
        string swapped = AnagramHelper.AnagramSwap(input);

        // Assert
        Assert.AreEqual(expectedSwapped, swapped);
    }

    [TestMethod]
    public void AnagramSwap_ShouldHandleSingleCharacter()
    {
        // Arrange
        string input = "a";
        string expectedSwapped = "a";

        // Act
        string swapped = AnagramHelper.AnagramSwap(input);

        // Assert
        Assert.AreEqual(expectedSwapped, swapped);
    }

    [TestMethod]
    public void AnagramRestore_ShouldHandleEmptyString()
    {
        // Arrange
        string input = "";
        string expectedRestored = "";

        // Act
        string restored = AnagramHelper.AnagramRestore(input);

        // Assert
        Assert.AreEqual(expectedRestored, restored);
    }

    [TestMethod]
    public void AnagramRestore_ShouldHandleSingleCharacter()
    {
        // Arrange
        string input = "a";
        string expectedRestored = "a";

        // Act
        string restored = AnagramHelper.AnagramRestore(input);

        // Assert
        Assert.AreEqual(expectedRestored, restored);
    }
}
