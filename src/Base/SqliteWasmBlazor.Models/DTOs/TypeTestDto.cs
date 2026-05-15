using MessagePack;
using SqliteWasmBlazor.Models.Models;

namespace SqliteWasmBlazor.Models.DTOs;

/// <summary>
/// MessagePack DTO for TypeTestEntity — covers ALL .NET types for V2 bulk round-trip testing.
/// [Key(n)] order must match the SQL column order used in INSERT statements.
/// </summary>
[MessagePackObject]
public class TypeTestDto
{
    [Key(0)] public int Id { get; set; }

    // Integer types
    [Key(1)] public byte ByteValue { get; set; }
    [Key(2)] public byte? NullableByteValue { get; set; }
    [Key(3)] public short ShortValue { get; set; }
    [Key(4)] public short? NullableShortValue { get; set; }
    [Key(5)] public int IntValue { get; set; }
    [Key(6)] public int? NullableIntValue { get; set; }
    [Key(7)] public long LongValue { get; set; }
    [Key(8)] public long? NullableLongValue { get; set; }

    // Floating point types
    [Key(9)] public float FloatValue { get; set; }
    [Key(10)] public float? NullableFloatValue { get; set; }
    [Key(11)] public double DoubleValue { get; set; }
    [Key(12)] public double? NullableDoubleValue { get; set; }
    [Key(13)] public decimal DecimalValue { get; set; }
    [Key(14)] public decimal? NullableDecimalValue { get; set; }

    // Boolean
    [Key(15)] public bool BoolValue { get; set; }
    [Key(16)] public bool? NullableBoolValue { get; set; }

    // String
    [Key(17)] public string StringValue { get; set; } = string.Empty;
    [Key(18)] public string? NullableStringValue { get; set; }

    // DateTime types
    [Key(19)] public DateTime DateTimeValue { get; set; }
    [Key(20)] public DateTime? NullableDateTimeValue { get; set; }
    [Key(21)] public DateTimeOffset DateTimeOffsetValue { get; set; }
    [Key(22)] public DateTimeOffset? NullableDateTimeOffsetValue { get; set; }
    [Key(23)] public TimeSpan TimeSpanValue { get; set; }
    [Key(24)] public TimeSpan? NullableTimeSpanValue { get; set; }

    // Guid (EF Core default = TEXT, NOT BLOB)
    [Key(25)] public Guid GuidValue { get; set; }
    [Key(26)] public Guid? NullableGuidValue { get; set; }

    // Binary data
    [Key(27)] public byte[]? BlobValue { get; set; }

    // Enum stored as int to avoid MessagePack source generator namespace conflict with TestEnum
    [Key(28)] public int EnumValue { get; set; }
    [Key(29)] public int? NullableEnumValue { get; set; }

    // Char
    [Key(30)] public char CharValue { get; set; }
    [Key(31)] public char? NullableCharValue { get; set; }

    // Collection (JSON TEXT via EF Core value converter)
    [Key(32)] public List<int> IntList { get; set; } = new();

    public static TypeTestDto FromEntity(TypeTestEntity e) => new()
    {
        Id = e.Id,
        ByteValue = e.ByteValue,
        NullableByteValue = e.NullableByteValue,
        ShortValue = e.ShortValue,
        NullableShortValue = e.NullableShortValue,
        IntValue = e.IntValue,
        NullableIntValue = e.NullableIntValue,
        LongValue = e.LongValue,
        NullableLongValue = e.NullableLongValue,
        FloatValue = e.FloatValue,
        NullableFloatValue = e.NullableFloatValue,
        DoubleValue = e.DoubleValue,
        NullableDoubleValue = e.NullableDoubleValue,
        DecimalValue = e.DecimalValue,
        NullableDecimalValue = e.NullableDecimalValue,
        BoolValue = e.BoolValue,
        NullableBoolValue = e.NullableBoolValue,
        StringValue = e.StringValue,
        NullableStringValue = e.NullableStringValue,
        DateTimeValue = e.DateTimeValue,
        NullableDateTimeValue = e.NullableDateTimeValue,
        DateTimeOffsetValue = e.DateTimeOffsetValue,
        NullableDateTimeOffsetValue = e.NullableDateTimeOffsetValue,
        TimeSpanValue = e.TimeSpanValue,
        NullableTimeSpanValue = e.NullableTimeSpanValue,
        GuidValue = e.GuidValue,
        NullableGuidValue = e.NullableGuidValue,
        BlobValue = e.BlobValue,
        EnumValue = (int)e.EnumValue,
        NullableEnumValue = e.NullableEnumValue is not null ? (int)e.NullableEnumValue : null,
        CharValue = e.CharValue,
        NullableCharValue = e.NullableCharValue,
        IntList = e.IntList
    };

    public TypeTestEntity ToEntity() => new()
    {
        Id = Id,
        ByteValue = ByteValue,
        NullableByteValue = NullableByteValue,
        ShortValue = ShortValue,
        NullableShortValue = NullableShortValue,
        IntValue = IntValue,
        NullableIntValue = NullableIntValue,
        LongValue = LongValue,
        NullableLongValue = NullableLongValue,
        FloatValue = FloatValue,
        NullableFloatValue = NullableFloatValue,
        DoubleValue = DoubleValue,
        NullableDoubleValue = NullableDoubleValue,
        DecimalValue = DecimalValue,
        NullableDecimalValue = NullableDecimalValue,
        BoolValue = BoolValue,
        NullableBoolValue = NullableBoolValue,
        StringValue = StringValue,
        NullableStringValue = NullableStringValue,
        DateTimeValue = DateTimeValue,
        NullableDateTimeValue = NullableDateTimeValue,
        DateTimeOffsetValue = DateTimeOffsetValue,
        NullableDateTimeOffsetValue = NullableDateTimeOffsetValue,
        TimeSpanValue = TimeSpanValue,
        NullableTimeSpanValue = NullableTimeSpanValue,
        GuidValue = GuidValue,
        NullableGuidValue = NullableGuidValue,
        BlobValue = BlobValue,
        EnumValue = (TestEnum)EnumValue,
        NullableEnumValue = NullableEnumValue is not null ? (TestEnum)NullableEnumValue : null,
        CharValue = CharValue,
        NullableCharValue = NullableCharValue,
        IntList = IntList
    };
}
